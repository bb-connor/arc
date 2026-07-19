impl ChioKernel {
    pub(crate) fn local_budget_event_authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: format!("kernel:{}", self.public_key().to_hex()),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        }
    }

    pub(crate) fn budget_backend_receipt_metadata(&self) -> Result<serde_json::Value, KernelError> {
        let (guarantee_level, authority_profile, metering_profile) =
            self.with_budget_store(|store| {
                Ok((
                    store.budget_guarantee_level().as_str().to_string(),
                    store.budget_authority_profile().as_str().to_string(),
                    store.budget_metering_profile().as_str().to_string(),
                ))
            })?;
        Ok(serde_json::json!({
            "budget_authority": {
                "guarantee_level": guarantee_level,
                "authority_profile": authority_profile,
                "metering_profile": metering_profile,
            }
        }))
    }

    pub(crate) fn budget_execution_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        terminal_event: Option<(&str, &BudgetHoldMutationDecision)>,
        execution_nonce_id: Option<&str>,
    ) -> serde_json::Value {
        let mut budget_authority = serde_json::Map::new();
        budget_authority.insert(
            "guarantee_level".to_string(),
            serde_json::json!(charge.authorize_metadata.guarantee_level.as_str()),
        );
        budget_authority.insert(
            "authority_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.budget_profile.as_str()),
        );
        budget_authority.insert(
            "metering_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.metering_profile.as_str()),
        );
        budget_authority.insert(
            "hold_id".to_string(),
            serde_json::json!(&charge.budget_hold_id),
        );
        if let Some(budget_term) = charge.authorize_metadata.budget_term() {
            budget_authority.insert("budget_term".to_string(), serde_json::json!(budget_term));
        }
        if let Some(authority) = charge.authorize_metadata.authority.as_ref() {
            budget_authority.insert(
                "authority".to_string(),
                serde_json::json!({
                    "authority_id": &authority.authority_id,
                    "lease_id": &authority.lease_id,
                    "lease_epoch": authority.lease_epoch,
                }),
            );
        }

        let mut authorize = serde_json::Map::new();
        if let Some(event_id) = charge.authorize_metadata.event_id.as_ref() {
            authorize.insert("event_id".to_string(), serde_json::json!(event_id));
        }
        if let Some(commit_index) = charge.authorize_metadata.budget_commit_index {
            authorize.insert(
                "budget_commit_index".to_string(),
                serde_json::json!(commit_index),
            );
        }
        authorize.insert(
            "exposure_units".to_string(),
            serde_json::json!(charge.cost_charged),
        );
        authorize.insert(
            "committed_cost_units_after".to_string(),
            serde_json::json!(charge.new_committed_cost_units),
        );
        budget_authority.insert(
            "authorize".to_string(),
            serde_json::Value::Object(authorize),
        );

        if let Some((disposition, terminal_event)) = terminal_event {
            let mut terminal = serde_json::Map::new();
            terminal.insert("disposition".to_string(), serde_json::json!(disposition));
            if let Some(event_id) = terminal_event.metadata.event_id.as_ref() {
                terminal.insert("event_id".to_string(), serde_json::json!(event_id));
            }
            if let Some(commit_index) = terminal_event.metadata.budget_commit_index {
                terminal.insert(
                    "budget_commit_index".to_string(),
                    serde_json::json!(commit_index),
                );
            }
            terminal.insert(
                "exposure_units".to_string(),
                serde_json::json!(terminal_event.exposure_units),
            );
            terminal.insert(
                "realized_spend_units".to_string(),
                serde_json::json!(terminal_event.realized_spend_units),
            );
            terminal.insert(
                "committed_cost_units_after".to_string(),
                serde_json::json!(terminal_event.committed_cost_units_after),
            );
            budget_authority.insert("terminal".to_string(), serde_json::Value::Object(terminal));
        }

        if let Some(nonce_id) = execution_nonce_id {
            budget_authority.insert(
                "execution_nonce_id".to_string(),
                serde_json::json!(nonce_id),
            );
            budget_authority.insert(
                "mediated_spend".to_string(),
                serde_json::json!({
                    "profile": chio_core_types::receipt::authoritative_spend::MEDIATED_SPEND_PROFILE
                }),
            );
        }

        serde_json::json!({ "budget_authority": budget_authority })
    }

    pub(crate) fn merge_budget_receipt_metadata(
        &self,
        extra_metadata: Option<serde_json::Value>,
        budget_metadata: serde_json::Value,
    ) -> Option<serde_json::Value> {
        let mut merged = match extra_metadata {
            Some(serde_json::Value::Object(mut metadata)) => {
                // budget_authority is a kernel-reserved namespace. Discard the
                // entire caller-supplied block before inserting verified store
                // and kernel state so omitted authoritative fields cannot be
                // inherited from untrusted metadata.
                metadata.remove("budget_authority");
                metadata
            }
            _ => serde_json::Map::new(),
        };

        if let serde_json::Value::Object(authoritative) = budget_metadata {
            for (key, value) in authoritative {
                merged.insert(key, value);
            }
        }

        Some(serde_json::Value::Object(merged))
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns the matched grant index and the exact pre-execution budget mutation.
    pub(crate) fn check_and_increment_budget(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
    ) -> Result<(usize, PreExecutionBudgetMutation), KernelError> {
        let mut saw_exhausted_budget = false;

        for matching in matching_grants {
            let grant = matching.grant;
            if cap.aggregate_invocation_budget.is_some()
                || request.supplemental_authorization.is_some()
            {
                let mutation = self.coordinate_ordinary_protocol_admission(
                    request,
                    cap,
                    matching.index,
                    grant,
                    current_unix_timestamp(),
                )?;
                return Ok((matching.index, mutation));
            }
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();

            if has_monetary {
                // Use worst-case max_cost_per_invocation as the pre-execution debit.
                let cost_units = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.units)
                    .unwrap_or(0);
                let currency = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.currency.clone())
                    .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                    .unwrap_or_else(|| "USD".to_string());
                let max_total = grant.max_total_cost.as_ref().map(|m| m.units);
                let max_per = grant.max_cost_per_invocation.as_ref().map(|m| m.units);
                let budget_total = max_total.unwrap_or(u64::MAX);
                let budget_hold_id = format!(
                    "budget-hold:{}:{}:{}",
                    request.request_id, cap.id, matching.index
                );
                let authorize_event_id = format!("{budget_hold_id}:authorize");
                let authority = self.local_budget_event_authority();

                // The recoverable money record commits in the SAME
                // transaction as the hold write, before the rail is touched:
                // a crash in any later window resolves through the journal
                // instead of leaving moved funds with no trace.
                let payment_journal = self.payment_journal_active().then(|| {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
                        .unwrap_or(0);
                    let rail = self
                        .payment_adapter
                        .as_ref()
                        .map(|adapter| adapter.rail_id().to_string())
                        .unwrap_or_default();
                    // Resolved exactly as the terminal receipt and the
                    // dispatch intent resolve it (request-scoped entry
                    // first, thread-local scope otherwise), so a recovered
                    // charge's reconciliation receipt is never dropped from
                    // the owning tenant's receipt view.
                    let tenant_id = self
                        .receipt_tenant_id_for_request(Some(&request.request_id))
                        .unwrap_or_else(current_scoped_receipt_tenant_id);
                    crate::payment::PaymentJournalRecord {
                        request_id: request.request_id.clone(),
                        capability_id: cap.id.clone(),
                        grant_index: matching.index as u32,
                        admission_operation: None,
                        authority: Some(authority.clone()),
                        hold_id: Some(budget_hold_id.clone()),
                        rail,
                        authorization_id: None,
                        transaction_id: None,
                        amount_units: cost_units,
                        budget_exposure_units: cost_units,
                        settle_action: None,
                        settle_amount_units: None,
                        currency: currency.clone(),
                        state: crate::payment::PaymentJournalState::HoldPlaced,
                        created_at_unix_ms: now_ms,
                        tenant_id,
                    }
                });

                let decision = self.with_budget_store(|store| {
                    let mut hold = BudgetAuthorizeHoldRequest::legacy(
                        cap.id.clone(),
                        matching.index,
                        grant.max_invocations,
                        cost_units,
                        max_per,
                        max_total,
                        Some(budget_hold_id.clone()),
                        Some(authorize_event_id),
                        Some(authority.clone()),
                    );
                    hold.payment_journal = payment_journal.clone();
                    Ok(store.authorize_budget_hold(hold)?)
                })?;
                match decision {
                    BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                        let charge = BudgetChargeResult {
                            grant_index: matching.index,
                            cost_charged: cost_units,
                            currency,
                            budget_total,
                            new_committed_cost_units: authorized.committed_cost_units_after,
                            budget_hold_id: authorized
                                .hold_id
                                .unwrap_or_else(|| budget_hold_id.clone()),
                            authorize_metadata: authorized.metadata,
                            admission_operation: None,
                        };
                        return Ok((
                            matching.index,
                            PreExecutionBudgetMutation::Charge(Box::new(charge)),
                        ));
                    }
                    BudgetAuthorizeHoldDecision::Denied(_) => {
                        saw_exhausted_budget = true;
                    }
                }
            } else {
                if grant.max_invocations.is_none() {
                    return Ok((matching.index, PreExecutionBudgetMutation::None));
                }

                if self.with_budget_store(|store| {
                    Ok(store.try_increment(&cap.id, matching.index, grant.max_invocations)?)
                })? {
                    return Ok((
                        matching.index,
                        PreExecutionBudgetMutation::Invocation {
                            grant_index: matching.index,
                        },
                    ));
                }
                saw_exhausted_budget = true;
            }
        }

        if saw_exhausted_budget {
            Err(KernelError::BudgetExhausted(cap.id.clone()))
        } else {
            // No matching grant had any limit -- allow with the first grant's index.
            let first_index = matching_grants.first().map(|m| m.index).unwrap_or(0);
            Ok((first_index, PreExecutionBudgetMutation::None))
        }
    }

    pub(crate) fn reverse_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReverseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                reversed_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reverse_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?)
        })
    }

    pub(crate) fn release_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReleaseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                released_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.release_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?)
        })
    }

    pub(crate) fn reverse_pre_execution_budget_mutation(
        &self,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        match budget_mutation {
            PreExecutionBudgetMutation::Charge(charge) => {
                self.reverse_budget_charge(&cap.id, charge).map(Some)
            }
            PreExecutionBudgetMutation::Invocation { grant_index } => {
                self.with_budget_store(|store| {
                    Ok(store.reverse_charge_cost(&cap.id, *grant_index, 0)?)
                })?;
                Ok(None)
            }
            PreExecutionBudgetMutation::Admission(admission) => self
                .reverse_ordinary_protocol_admission(cap, admission.as_ref())
                .map(Some),
            PreExecutionBudgetMutation::None => Ok(None),
        }
    }

    /// Whether the registered tool server for `server_id` measures the realized
    /// cost of an invocation it dispatches.
    ///
    /// An absent server defaults to `true` (measured), preserving
    /// reconcile-and-settle behavior for every real server. The server is
    /// always present here because dispatch resolved it before finalization, so
    /// the default is unreachable in practice.
    pub(crate) fn tool_server_measures_realized_cost(&self, server_id: &str) -> bool {
        self.tool_servers
            .get(server_id)
            .is_none_or(|server| server.measures_realized_cost())
    }

    /// Finalize a tool output whose realized cost was not measured on this path.
    ///
    /// A tool server that reports `measures_realized_cost() == false` did not
    /// execute the target tool, so no realized cost exists here. The kernel must
    /// not sign a settled, reconciled authoritative spend for it: instead it
    /// reverses the pre-execution hold (nothing was spent on this path) and
    /// emits a provisional allow receipt whose budget authority carries a
    /// `reversed` terminal and whose settlement stays `pending`. Such a receipt
    /// is rejected by `is_authoritative_spend_receipt` (the hold is not
    /// reconciled). Real reconciliation happens at the execution site.
    fn finalize_unmeasured_cost_provisional_allow(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        charge: BudgetChargeResult,
        security_context: Option<&SecurityInvocationContext>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let reverse = self.reverse_budget_charge(&cap.id, &charge)?;
        let running_committed_cost_units = reverse.committed_cost_units_after;
        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_committed_cost_units);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        // The nonce id is intentionally omitted from the budget authority so the
        // receipt makes no `mediated_spend` profile claim: this is a provisional
        // confirmation, not an authoritative spend.
        let budget_metadata =
            self.budget_execution_receipt_metadata(&charge, Some(("reversed", &reverse)), None);
        let merged = merge_metadata_objects(
            financial_json,
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
        );
        let post_invocation = if security_context.is_some() {
            self.apply_post_invocation_pipeline(
                request,
                limited_output,
                Some(charge.grant_index),
                security_context,
                merged,
            )?
        } else {
            PostInvocationHandling {
                output: limited_output,
                extra_metadata: merged,
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
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    post_invocation.extra_metadata,
                    // This provisional allow already reversed the budget hold and
                    // did not execute the tool at the kernel, so there is no
                    // reserved hold to reconcile and nothing to authorize
                    // downstream. Emit no execution nonce: a spendable nonce here
                    // would carry no reserved hold, letting a gate deployment
                    // execute against a refunded hold and spend outside the cap.
                    AllowResponseNonce::Suppressed,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    // The tool ran (a side effect may have committed) but the
                    // stream ended incomplete, so any runtime-admission lease
                    // consumed at admission is retained, not released. Mark it
                    // so the burned lease is recoverable from the receipt.
                    self.mark_runtime_admission_reservations_retained_fail_closed(
                        post_invocation.extra_metadata,
                    ),
                ),
        }
    }


    /// Prepaid quote amount for a MustPrepay intent, if one applies.
    ///
    /// This is the authorization amount when the grant carries no monetary
    /// ceiling, so the same figure settles the hold after execution and is the
    /// amount refunded when a settled-at-authorize invocation is aborted.
    pub(crate) fn mustprepay_quoted_amount(request: &ToolCallRequest) -> Option<(u64, String)> {
        request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.as_tool_invocation())
            .and_then(|intent| intent.metered_billing.as_ref())
            .filter(|metered| {
                metered.settlement_mode
                    == chio_core::capability::governance::MeteredSettlementMode::MustPrepay
            })
            .map(|metered| {
                (
                    metered.quote.quoted_cost.units,
                    metered.quote.quoted_cost.currency.clone(),
                )
            })
    }

    /// Whether `request` carries a governed MustPrepay intent, i.e. one whose
    /// metered billing mandates prepayment before the tool executes.
    pub(crate) fn is_governed_mustprepay_request(request: &ToolCallRequest) -> bool {
        Self::mustprepay_quoted_amount(request).is_some()
    }

    /// Satisfy the governed MustPrepay prepayment gate before a reserve-for-caller
    /// authorization nonce is minted.
    ///
    /// The reserve-for-caller path never dispatches the tool on this kernel: the
    /// caller presents the minted nonce to a downstream tool server, which
    /// reconciles the reserved budget hold without re-entering payment
    /// authorization. A MustPrepay intent therefore has no later settlement point,
    /// so the prepayment must be authorized AND settled here, before the nonce
    /// exists. Otherwise a reserved nonce would let the caller execute a MustPrepay
    /// spend downstream with no payment ever occurring.
    ///
    /// The prepayment is settled at the intent's quoted cost (the amount that will
    /// actually be prepaid), independently of the reserved budget hold that stays
    /// open for `max_total_cost` accounting and is reconciled downstream.
    ///
    /// Returns `Ok(None)` when the request is not a governed MustPrepay intent
    /// (nothing to prepay). Returns `Ok(Some(authorization))` carrying the settled
    /// prepayment so the caller can refund it if minting or persisting the
    /// reservation then fails, which would otherwise leave the payer captured for a
    /// reservation that was never handed out. Returns `Err` so the caller denies
    /// fail-closed when the prepayment cannot be authorized or settled; any
    /// unsettled hold is released so the payer's funds are not left frozen.
    pub(crate) fn ensure_reserved_mustprepay_prepaid(
        &self,
        request: &ToolCallRequest,
        charge_result: Option<&BudgetChargeResult>,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        existing_authorization: Option<&PaymentAuthorization>,
    ) -> Result<Option<ReservedPrepayment>, KernelError> {
        if !Self::is_governed_mustprepay_request(request) {
            return Ok(None);
        }
        let authorization = match existing_authorization {
            Some(authorization) => Some(authorization.clone()),
            None => self
                .authorize_payment_if_needed(request, charge_result, admission_operation)
                .map_err(|error| {
                    KernelError::GovernedTransactionDenied(format!(
                        "MustPrepay prepayment authorization failed before reserving an execution nonce: {error}"
                    ))
                })?,
        };
        let Some(authorization) = authorization else {
            return Err(KernelError::GovernedTransactionDenied(
                "MustPrepay intent reached the reserve-for-caller path without an authorized prepayment".to_string(),
            ));
        };
        match self.settle_prepaid_authorization_without_charge(
            request,
            &authorization,
            charge_result,
            admission_operation,
        )? {
            // The prepayment is now captured. Report it as settled so a later
            // reservation tear-down refunds it rather than releasing an already
            // captured hold, and carry the rail reference so the downstream
            // reconcile receipt can name the transaction that funded the spend.
            Some(settlement) => Ok(Some(ReservedPrepayment {
                authorization: PaymentAuthorization {
                    settled: true,
                    ..authorization
                },
                payment_reference: settlement.payment_reference,
            })),
            None => Err(KernelError::GovernedTransactionDenied(
                "MustPrepay prepayment could not be settled before reserving an execution nonce"
                    .to_string(),
            )),
        }
    }

    /// Settle a prepaid authorization for a MustPrepay call whose grant carries
    /// no monetary ceiling (no budget charge to reconcile).
    ///
    /// An adapter that already settled the hold is folded through unchanged. An
    /// unsettled hold is captured at the prepaid quote amount. Returns `None`
    /// when the hold cannot be settled so the caller fails closed.
    fn settle_prepaid_authorization_without_charge(
        &self,
        request: &ToolCallRequest,
        authorization: &PaymentAuthorization,
        charge_result: Option<&BudgetChargeResult>,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
    ) -> Result<Option<ReceiptSettlement>, KernelError> {
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "payment authorization present without configured adapter".to_string(),
            )
        })?;
        let journaled = charge_result.is_some() || admission_operation.is_some();
        if authorization.settled {
            if !journaled {
                return Ok(Some(ReceiptSettlement::from_authorization(authorization)));
            }
            let transaction_id = self
                .resolve_settled_authorization_transaction_reference(
                    request,
                    admission_operation,
                    authorization,
                    adapter.as_ref(),
                )
                .map_err(|error| {
                    KernelError::GovernedTransactionDenied(format!(
                        "settled MustPrepay authorization omitted its exact transaction: {error}"
                    ))
                })?;
            self.advance_payment_journal_if_active(
                &request.request_id,
                crate::payment::PaymentJournalState::Authorized,
                crate::payment::PaymentJournalState::Settled,
                None,
                Some(&transaction_id),
                None,
            )?;
            return Ok(Some(ReceiptSettlement {
                payment_reference: Some(transaction_id),
                settlement_status: SettlementStatus::Settled,
            }));
        }
        let Some((amount_units, currency)) = Self::mustprepay_quoted_amount(request) else {
            warn!(
                request_id = %request.request_id,
                authorization_id = %authorization.authorization_id,
                "prepaid authorization lacks a resolvable quote amount; denying fail-closed"
            );
            Self::release_unsettled_prepaid_hold(
                &**adapter,
                request,
                authorization,
                admission_operation,
            );
            return Ok(None);
        };
        if journaled {
            self.advance_payment_journal_if_active(
                &request.request_id,
                crate::payment::PaymentJournalState::Authorized,
                crate::payment::PaymentJournalState::Settling,
                None,
                None,
                Some(crate::payment::PaymentSettleIntent {
                    action: crate::payment::PaymentSettleAction::Capture,
                    amount_units: Some(amount_units),
                }),
            )?;
        }
        let capture = || match admission_operation {
            Some(binding) => adapter.capture_for_operation(OperationPaymentCaptureRequest {
                operation_id: binding.operation_id(),
                request_binding_hash: binding.request_binding_hash(),
                authorization_id: &authorization.authorization_id,
                amount_units,
                currency: &currency,
                reference: &request.request_id,
            }),
            None => adapter.capture(
                &authorization.authorization_id,
                amount_units,
                &currency,
                &request.request_id,
            ),
        };
        let result = capture();
        let result = if admission_operation.is_some() {
            result.or_else(|_| capture())
        } else {
            result
        };
        match result {
            Ok(result) => {
                let settlement = ReceiptSettlement::from_payment_result(&result);
                if settlement.settlement_status == SettlementStatus::Settled {
                    if journaled {
                        self.advance_payment_journal_if_active(
                            &request.request_id,
                            crate::payment::PaymentJournalState::Settling,
                            crate::payment::PaymentJournalState::Settled,
                            None,
                            Some(&result.transaction_id),
                            None,
                        )?;
                    }
                    Ok(Some(settlement))
                } else {
                    warn!(
                        request_id = %request.request_id,
                        authorization_id = %authorization.authorization_id,
                        "prepaid authorization capture did not settle; denying fail-closed"
                    );
                    if !journaled {
                        Self::release_unsettled_prepaid_hold(
                            &**adapter,
                            request,
                            authorization,
                            admission_operation,
                        );
                    }
                    Ok(None)
                }
            }
            Err(error) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "prepaid authorization capture failed; denying fail-closed"
                );
                if !journaled {
                    Self::release_unsettled_prepaid_hold(
                        &**adapter,
                        request,
                        authorization,
                        admission_operation,
                    );
                }
                Ok(None)
            }
        }
    }

    /// Best-effort void of an unsettled prepaid hold when a MustPrepay call fails
    /// closed after execution, so the payer's funds are not left frozen at the
    /// facilitator until the authorization expires. Logs on failure and never
    /// propagates: the call is denied regardless of whether the release lands.
    fn release_unsettled_prepaid_hold(
        adapter: &dyn PaymentAdapter,
        request: &ToolCallRequest,
        authorization: &PaymentAuthorization,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
    ) {
        let release = || match admission_operation {
            Some(binding) => adapter.release_for_operation(
                binding.operation_id(),
                binding.request_binding_hash(),
                &authorization.authorization_id,
                &request.request_id,
            ),
            None => adapter.release(&authorization.authorization_id, &request.request_id),
        };
        let result = release();
        let result = if admission_operation.is_some() {
            result.or_else(|_| release())
        } else {
            result
        };
        if let Err(error) = result {
            warn!(
                request_id = %request.request_id,
                authorization_id = %authorization.authorization_id,
                reason = %redacted!(&error),
                "failed to release unsettled prepaid authorization on fail-closed deny"
            );
        }
    }

    /// Refund a captured MustPrepay prepayment when a reserve-for-caller
    /// reservation tears down after the prepayment settled but before the caller
    /// receives a usable nonce (the reservation stamp reversed the budget hold, or
    /// the reserved receipt failed to persist). The prepayment was captured at the
    /// quoted cost before the nonce could be minted, so without this the payer
    /// would stay charged for a reservation that was denied. Refunds the prepaid
    /// quote through the same unwind path a mid-execution abort uses, with no
    /// budget charge to reverse. Logs on failure and never propagates: the
    /// reservation is denied regardless, and the original tear-down error is the
    /// one surfaced to the caller.
    pub(crate) fn refund_reserved_mustprepay_prepayment(
        &self,
        request: &ToolCallRequest,
        budget_mutation: &PreExecutionBudgetMutation,
        prepayment: &ReservedPrepayment,
    ) {
        let Some((amount_units, currency)) = Self::mustprepay_quoted_amount(request) else {
            warn!(
                request_id = %request.request_id,
                "failed to refund captured MustPrepay prepayment: quote is unavailable"
            );
            return;
        };
        let binding = budget_mutation.admission_operation_binding();
        if let Some(binding) = binding {
            let cleanup = self
                .load_ordinary_admission(binding.operation_id())
                .and_then(|operation| {
                    if operation.request_binding_hash() != binding.request_binding_hash() {
                        return Err(KernelError::Internal(
                            "reserved prepayment cleanup operation binding mismatch".to_string(),
                        ));
                    }
                    self.execute_reserved_payment_cleanup(
                        &operation,
                        amount_units,
                        currency,
                        request.request_id.clone(),
                    )
                });
            if let Err(error) = cleanup {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %prepayment.authorization.authorization_id,
                    reason = %redacted!(&error),
                    "failed to durably refund captured MustPrepay prepayment after reserve tear-down"
                );
            }
            return;
        }
        let Some(adapter) = self.payment_adapter.as_ref() else {
            warn!(
                request_id = %request.request_id,
                "failed to refund captured MustPrepay prepayment: payment adapter is unavailable"
            );
            return;
        };
        let transaction_id = prepayment
            .payment_reference
            .as_deref()
            .unwrap_or(&prepayment.authorization.authorization_id);
        let refund = || {
            adapter.refund(
                transaction_id,
                amount_units,
                &currency,
                &request.request_id,
            )
        };
        let result = refund();
        if let Err(error) = result {
            warn!(
                request_id = %request.request_id,
                authorization_id = %prepayment.authorization.authorization_id,
                reason = %redacted!(&error),
                "failed to refund captured MustPrepay prepayment after reserve tear-down"
            );
        }
    }
}
