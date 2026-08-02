impl ChioKernel {
    fn partition_escrow_receipt_metadata(
        authorize: &BudgetCommitMetadata,
        terminal: Option<&BudgetCommitMetadata>,
    ) -> Result<
        Option<chio_core_types::receipt::economics::FinancialPartitionEscrowReceiptMetadata>,
        KernelError,
    >
    {
        if authorize.guarantee_level != BudgetGuaranteeLevel::PartitionEscrowed {
            if authorize.partition_escrow_evidence.is_some()
                || terminal.is_some_and(|metadata| {
                    metadata.guarantee_level != authorize.guarantee_level
                        || metadata.partition_escrow_evidence.is_some()
                })
            {
                return Err(KernelError::Internal(
                    "non-partition receipt lineage carried partition escrow evidence or changed guarantee"
                        .to_string(),
                ));
            }
            return Ok(None);
        }
        let commit_evidence = authorize.partition_escrow_evidence.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "partition-escrowed receipt lineage omitted signed allocation evidence".to_string(),
            )
        })?;
        if terminal.is_some_and(|metadata| {
            metadata.guarantee_level != BudgetGuaranteeLevel::PartitionEscrowed
                || metadata.partition_escrow_evidence.as_ref() != Some(commit_evidence)
        }) {
            return Err(KernelError::Internal(
                "partition escrow receipt lineage changed after authorization".to_string(),
            ));
        }
        let evidence = commit_evidence.evidence().map_err(|error| {
            KernelError::Internal(format!(
                "partition escrow receipt evidence is invalid: {error}"
            ))
        })?;
        let resolver = evidence.resolver();
        let durable_store = evidence.durable_store();
        Ok(Some(
            chio_core_types::receipt::economics::FinancialPartitionEscrowReceiptMetadata {
                canonical_json: commit_evidence.canonical_json().to_string(),
                evidence_digest: commit_evidence.evidence_digest().to_string(),
                summary:
                    chio_core_types::receipt::economics::FinancialPartitionEscrowReceiptSummary {
                        resolver_id: resolver.resolver_id().to_string(),
                        resolver_implementation_id: resolver.implementation_id().to_string(),
                        resolver_implementation_version: resolver.implementation_version(),
                        resolver_configuration_digest: resolver.configuration_digest().to_string(),
                        store_identity_digest: durable_store.store_identity_digest().to_string(),
                        counter_namespace_digest: durable_store
                            .counter_namespace_digest()
                            .to_string(),
                        fencing_token: durable_store.fencing_token(),
                        partition_id: evidence.partition_id().to_string(),
                        authority_id: evidence.authority_id().to_string(),
                    },
            },
        ))
    }

    pub(crate) fn local_budget_event_authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: format!("kernel:{}", self.public_key().to_hex()),
            lease_id: "single-node".to_string(),
            lease_epoch: 1,
        }
    }

    pub(crate) fn budget_event_authority(&self) -> BudgetEventAuthority {
        self.partition_escrow_registry.as_ref().map_or_else(
            || self.local_budget_event_authority(),
            |registry| {
                let fencing_token = registry.durable_store().fencing_token();
                BudgetEventAuthority {
                    authority_id: registry.authority_id().to_string(),
                    lease_id: format!("{}:fence:{fencing_token}", registry.partition_id()),
                    lease_epoch: fencing_token,
                }
            },
        )
    }

    pub(crate) fn budget_execution_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        terminal_event: Option<(&str, &BudgetHoldMutationDecision)>,
        execution_nonce_id: Option<&str>,
    ) -> Result<serde_json::Value, KernelError> {
        if let Some((disposition, terminal)) = terminal_event {
            let (
                expected_event_id,
                expected_realized_spend_units,
                expected_invocation_state,
                expected_monetary_state,
                expected_mutation_kind,
            ) = match disposition {
                "reversed" => (
                    charge.reverse_event_id(),
                    0,
                    BudgetInvocationReservationState::Reversed,
                    if charge.cost_charged == 0 {
                        BudgetMonetaryHoldState::None
                    } else {
                        BudgetMonetaryHoldState::Reversed
                    },
                    if charge.admission_operation.is_some() {
                        crate::budget_store::BudgetMutationKind::ReverseInvocations
                    } else {
                        crate::budget_store::BudgetMutationKind::ReverseExposure
                    },
                ),
                "released" => (
                    charge.release_event_id(),
                    0,
                    if charge.admission_operation.is_some() {
                        BudgetInvocationReservationState::Captured
                    } else {
                        BudgetInvocationReservationState::Absent
                    },
                    BudgetMonetaryHoldState::Released,
                    crate::budget_store::BudgetMutationKind::ReleaseExposure,
                ),
                "reconciled" => (
                    charge.reconcile_event_id(),
                    terminal.realized_spend_units,
                    if charge.admission_operation.is_some() {
                        BudgetInvocationReservationState::Captured
                    } else {
                        BudgetInvocationReservationState::Absent
                    },
                    BudgetMonetaryHoldState::Reconciled,
                    crate::budget_store::BudgetMutationKind::ReconcileSpend,
                ),
                _ => {
                    return Err(KernelError::Internal(
                        "unsupported budget receipt terminal disposition".to_string(),
                    ));
                }
            };
            if terminal.realized_spend_units > charge.cost_charged {
                return Err(KernelError::GuardDenied(
                    "receipt budget terminal realized spend exceeds its authorized exposure"
                        .to_string(),
                ));
            }
            self.with_budget_store(|store| {
                self.validate_budget_terminal_decision_for_store(
                    store,
                    terminal,
                    BudgetTerminalDecisionExpectation {
                        authorization_metadata: &charge.authorize_metadata,
                        expected_event_id: &expected_event_id,
                        expected_authority: charge.authorize_metadata.authority.as_ref(),
                        expected_capability_id: None,
                        expected_grant_index: charge.grant_index,
                        expected_hold_id: &charge.budget_hold_id,
                        expected_admission_operation: charge.admission_operation.as_ref(),
                        expected_mutation_kind,
                        expected_exposure_units: charge.cost_charged,
                        expected_realized_spend_units,
                        expected_invocation_state,
                        expected_monetary_state,
                        stage: "receipt terminal projection",
                    },
                )
            })?;
        }
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
        if let Some(partition_escrow) = Self::partition_escrow_receipt_metadata(
            &charge.authorize_metadata,
            terminal_event.map(|(_, event)| &event.metadata),
        )? {
            budget_authority.insert(
                "partition_escrow".to_string(),
                serde_json::json!(partition_escrow),
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

        Ok(serde_json::json!({ "budget_authority": budget_authority }))
    }

    pub(crate) fn merge_budget_receipt_metadata(
        &self,
        extra_metadata: Option<serde_json::Value>,
        budget_metadata: serde_json::Value,
    ) -> Option<serde_json::Value> {
        let mut merged = match extra_metadata {
            Some(serde_json::Value::Object(mut metadata)) => {
                // Budget authority namespaces are kernel-reserved. Discard
                // caller-supplied blocks before inserting verified state so
                // omitted authoritative fields cannot be inherited.
                metadata.remove("budget_authority");
                metadata.remove("budget_denial_authority");
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

    pub(crate) fn ambiguous_dispatch_receipt_metadata(
        &self,
        budget_mutation: &PreExecutionBudgetMutation,
        payment_authorization: Option<&PaymentAuthorization>,
        runtime_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let retained = match budget_mutation.charge_result() {
            Some(charge) => match self.budget_execution_receipt_metadata(charge, None, None) {
                Ok(mut budget_metadata) => {
                    if let Some(authority) = budget_metadata
                        .get_mut("budget_authority")
                        .and_then(serde_json::Value::as_object_mut)
                    {
                        authority.insert(
                            "admission_retained".to_string(),
                            serde_json::Value::Bool(true),
                        );
                    }
                    self.merge_budget_receipt_metadata(runtime_metadata, budget_metadata)
                }
                Err(error) => merge_metadata_objects(
                    runtime_metadata,
                    Some(serde_json::json!({
                        "budget_authority": {
                            "admission_retained": true,
                            "retention_projection_error": error.to_string()
                        }
                    })),
                ),
            },
            None => match budget_mutation.admission_operation_binding() {
                Some(binding) => merge_metadata_objects(
                    runtime_metadata,
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "retained_admission_operation_id": binding.operation_id(),
                            "retained_request_binding_hash": binding.request_binding_hash(),
                            "admission_retained": true
                        }
                    })),
                ),
                None => runtime_metadata,
            },
        };
        match payment_authorization {
            Some(authorization) => merge_metadata_objects(
                retained,
                Some(serde_json::json!({
                    "financial": {
                        "payment_reference": authorization.authorization_id,
                        "payment_authorization_retained": true
                    }
                })),
            ),
            None => retained,
        }
    }

    pub(crate) fn sanitize_budget_authorization_denial_metadata(
        &self,
        extra_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let mut sanitized = self.merge_budget_receipt_metadata(
            extra_metadata,
            serde_json::Value::Object(serde_json::Map::new()),
        )?;
        if let serde_json::Value::Object(metadata) = &mut sanitized {
            metadata.remove("financial");
            metadata.remove("governed_transaction");
        }
        Some(sanitized)
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns the matched grant index and the exact pre-execution budget mutation.
    pub(crate) fn check_and_increment_budget(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
        caller_reservation: bool,
        caller_receipt_metadata: Option<&serde_json::Value>,
    ) -> Result<(usize, PreExecutionBudgetMutation), KernelError> {
        if let Some(matching) = matching_grants.first() {
            let grant = matching.grant;
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();
            if caller_reservation
                || has_monetary
                || grant.max_invocations.is_some()
                || cap.aggregate_invocation_budget.is_some()
                || grant.constraints.iter().any(|constraint| {
                    matches!(
                        constraint,
                        Constraint::RequireCumulativeApprovalAbove { .. }
                    )
                })
                || request.supplemental_quota_authorization().is_some()
                || self.partition_escrow_registry.is_some()
                || Self::is_governed_mustprepay_request(request)
            {
                let mutation = self.coordinate_ordinary_protocol_admission(
                    request,
                    cap,
                    matching.index,
                    grant,
                    caller_reservation,
                    caller_receipt_metadata,
                    current_unix_timestamp(),
                )?;
                return Ok((matching.index, mutation));
            }
            return Ok((matching.index, PreExecutionBudgetMutation::None));
        }

        Ok((0, PreExecutionBudgetMutation::None))
    }

    pub(crate) fn reverse_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReverseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            let reversed = store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                reversed_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reverse_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?;
            self.validate_budget_terminal_decision_for_store(
                store,
                &reversed,
                BudgetTerminalDecisionExpectation {
                    authorization_metadata: &charge.authorize_metadata,
                    expected_event_id: &charge.reverse_event_id(),
                    expected_authority: charge.authorize_metadata.authority.as_ref(),
                    expected_capability_id: Some(capability_id),
                    expected_grant_index: charge.grant_index,
                    expected_hold_id: &charge.budget_hold_id,
                    expected_admission_operation: charge.admission_operation.as_ref(),
                    expected_mutation_kind: if charge.admission_operation.is_some() {
                        crate::budget_store::BudgetMutationKind::ReverseInvocations
                    } else {
                        crate::budget_store::BudgetMutationKind::ReverseExposure
                    },
                    expected_exposure_units: charge.cost_charged,
                    expected_realized_spend_units: 0,
                    expected_invocation_state: BudgetInvocationReservationState::Reversed,
                    expected_monetary_state: if charge.cost_charged == 0 {
                        BudgetMonetaryHoldState::None
                    } else {
                        BudgetMonetaryHoldState::Reversed
                    },
                    stage: "budget reverse",
                },
            )?;
            Ok(reversed)
        })
    }

    pub(crate) fn release_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReleaseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            let released = store.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                released_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.release_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?;
            self.validate_budget_terminal_decision_for_store(
                store,
                &released,
                BudgetTerminalDecisionExpectation {
                    authorization_metadata: &charge.authorize_metadata,
                    expected_event_id: &charge.release_event_id(),
                    expected_authority: charge.authorize_metadata.authority.as_ref(),
                    expected_capability_id: Some(capability_id),
                    expected_grant_index: charge.grant_index,
                    expected_hold_id: &charge.budget_hold_id,
                    expected_admission_operation: charge.admission_operation.as_ref(),
                    expected_mutation_kind:
                        crate::budget_store::BudgetMutationKind::ReleaseExposure,
                    expected_exposure_units: charge.cost_charged,
                    expected_realized_spend_units: 0,
                    expected_invocation_state: if charge.admission_operation.is_some() {
                        BudgetInvocationReservationState::Captured
                    } else {
                        BudgetInvocationReservationState::Absent
                    },
                    expected_monetary_state: BudgetMonetaryHoldState::Released,
                    stage: "budget release",
                },
            )?;
            Ok(released)
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
    /// execute the target tool, so no realized monetary cost exists here. The
    /// kernel must not sign a settled, reconciled authoritative spend for it:
    /// instead it releases the pre-execution monetary exposure while retaining
    /// the captured invocation and
    /// emits a provisional allow receipt whose budget authority carries a
    /// `reversed` terminal and whose settlement stays `pending`. Such a receipt
    /// is rejected by `is_authoritative_spend_receipt` (the hold is not
    /// reconciled). Real reconciliation happens at the execution site.
    #[allow(clippy::too_many_arguments)]
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
        let release = self.release_budget_charge(&cap.id, &charge)?;
        let running_committed_cost_units = release.committed_cost_units_after;
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
            self.budget_execution_receipt_metadata(&charge, Some(("released", &release)), None)?;
        let mut extra_metadata = extra_metadata;
        strip_reserved_economic_receipt_metadata(&mut extra_metadata);
        let merged = merge_metadata_objects(
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
            financial_json,
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
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<Option<ReservedPrepayment>, KernelError> {
        if !Self::is_governed_mustprepay_request(request) {
            return Ok(None);
        }
        let authorization = match existing_authorization {
            Some(authorization) => Some(authorization.clone()),
            None => self
                .authorize_payment_if_needed(
                    request,
                    charge_result,
                    admission_operation,
                    verified_payee_binding,
                )
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
