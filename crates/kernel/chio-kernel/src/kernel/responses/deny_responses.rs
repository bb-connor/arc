use super::*;

impl ChioKernel {
    pub(in crate::kernel) fn monetary_deny_metadata(
        &self,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
    ) -> Result<(Option<usize>, Option<serde_json::Value>), KernelError> {
        let Some(mg) = matching_grants.iter().find(|matching| {
            matching.grant.max_cost_per_invocation.is_some()
                || matching.grant.max_total_cost.is_some()
        }) else {
            return Ok((None, None));
        };
        let grant = mg.grant;
        let currency = grant
            .max_cost_per_invocation
            .as_ref()
            .map(|m| m.currency.clone())
            .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
            .unwrap_or_else(|| "USD".to_string());
        let budget_total = grant.max_total_cost.as_ref().map(|m| m.units);
        let attempted_cost = grant
            .max_cost_per_invocation
            .as_ref()
            .map(|m| m.units)
            .unwrap_or(0);
        let delegation_depth = crate::receipt_support::checked_receipt_count(
            cap.delegation_chain.len(),
            "delegation depth",
        )?;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) =
            ReceiptSettlement::not_applicable().into_receipt_parts();

        let usage = self.with_budget_store(|store| Ok(store.get_usage(&cap.id, mg.index)?))?;
        let committed = usage
            .map(|usage| usage.committed_cost_units())
            .transpose()?
            .unwrap_or(0);
        let budget_remaining = financial_budget_remaining(budget_total, committed)?;
        let financial_meta = FinancialReceiptMetadata {
            grant_index: crate::receipt_support::checked_receipt_count(mg.index, "grant index")?,
            cost_charged: 0,
            currency,
            budget_remaining,
            budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: Some(attempted_cost),
        };
        Ok((
            Some(mg.index),
            Some(serde_json::json!({ "financial": financial_meta })),
        ))
    }

    pub(crate) fn build_monetary_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
        extra_metadata: RefusalReceiptMetadata,
    ) -> Result<ToolCallResponse, KernelError> {
        let (matched_grant_index, financial_metadata) =
            self.monetary_deny_metadata(matching_grants, cap)?;
        if let Some(matched_grant_index) = matched_grant_index {
            let extra_metadata =
                self.prepare_refusal_receipt_metadata(&request.request_id, extra_metadata)?;
            let deny_extra_metadata =
                merge_metadata_objects(financial_metadata.clone(), extra_metadata.clone());
            let request_metadata = request_receipt_metadata(
                request,
                self.attestation_trust_policy.as_ref(),
                timestamp,
                deny_extra_metadata.as_ref(),
            )?;

            let metadata = merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(matched_grant_index))?,
                    deny_extra_metadata,
                ),
                request_metadata,
            );
            let receipt_content = receipt_content_for_output(None, None)?;

            let action =
                ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
                    KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
                })?;

            let receipt = self.build_and_sign_receipt(ReceiptParams {
                request_id: Some(&request.request_id),
                capability_id: &cap.id,
                tool_name: &request.tool_name,
                server_id: &request.server_id,
                decision: Decision::Deny {
                    reason: reason.to_string(),
                    guard: "kernel".to_string(),
                },
                action,
                content_hash: receipt_content.content_hash,
                canonical_content: receipt_content.canonical_content,
                metadata,
                timestamp,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
            })?;

            self.record_chio_receipt_with_federation(request, &receipt)?;

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

    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    pub(crate) fn build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_execution_monetary_deny_response_with_recording(
            request,
            reason,
            timestamp,
            charge,
            committed_cost_after_release,
            cap,
            extra_metadata,
            verified_payee_binding,
            ReceiptRecordMode::WithFederation,
        )
    }

    /// Financial receipt metadata for a pre-execution budget hold that never
    /// reached dispatch: nothing is charged and the attempted cost is recorded.
    pub(crate) fn pre_execution_financial_metadata(
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let delegation_depth = crate::receipt_support::checked_receipt_count(
            cap.delegation_chain.len(),
            "delegation depth",
        )?;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) =
            ReceiptSettlement::not_applicable().into_receipt_parts();
        let budget_remaining =
            financial_budget_remaining(charge.budget_total, committed_cost_after_release)?;

        let financial_meta = FinancialReceiptMetadata {
            grant_index: crate::receipt_support::checked_receipt_count(
                charge.grant_index,
                "grant index",
            )?,
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
        Ok(Some(serde_json::json!({ "financial": financial_meta })))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    fn build_pre_execution_monetary_deny_response_with_recording(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
        record_mode: ReceiptRecordMode,
    ) -> Result<ToolCallResponse, KernelError> {
        let extra_metadata =
            self.prepare_refusal_receipt_metadata(&request.request_id, extra_metadata)?;
        let financial_metadata =
            Self::pre_execution_financial_metadata(charge, committed_cost_after_release, cap)?;
        let deny_extra_metadata =
            merge_metadata_objects(financial_metadata.clone(), extra_metadata.clone());
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            deny_extra_metadata.as_ref(),
            verified_payee_binding,
        )?;

        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(charge.grant_index))?,
                    deny_extra_metadata,
                ),
                request_metadata,
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_mode(request, &receipt, record_mode)?;

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

    fn build_local_v1_failclosed_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        guard: &str,
    ) -> Result<ToolCallResponse, KernelError> {
        let extra_metadata = self.prepare_refusal_receipt_metadata(
            &request.request_id,
            RefusalReceiptMetadata::new(extra_metadata, IdentityDisposition::Reusable),
        )?;
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: guard.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index)?,
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        // A fail-closed deny admits no tool, so it must always surface as a signed
        // verdict rather than a 500. When the deny fires because durable
        // persistence is down, appending to that same closed store would fail and
        // mask the verdict, so this records best-effort and never fails the deny on
        // a serving-closed store.
        self.record_failclosed_deny_receipt(&receipt)?;

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

    /// Build a Deny response for the pre-dispatch federation admission
    /// gate. By definition the named federation peer is NOT pinned fresh
    /// on this path, so we cannot run the federation cosign hook because it
    /// would attempt the same peer-freshness lookup that just failed. The
    /// v1 deny receipt is signed by the local kernel and persisted as
    /// evidence of the closed admission.
    pub(crate) fn build_negotiation_failclosed_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Local record only: skip `record_chio_receipt_with_federation`
        // because that helper would re-run the freshness check we just
        // lost. The fail-closed deny is intentionally non-federated.
        self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            "kernel.negotiation",
        )
    }

    /// Build a Deny response for the emergency stop gate. The stopped-kernel
    /// path must not perform federation peer lookup or remote co-signing,
    /// because the kill switch is stronger than negotiation state and must
    /// always surface the emergency reason.
    pub(crate) fn build_emergency_stop_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // A stop denial is definite and precedes any effect, so the request
        // may be retried under the same id after resume.
        let mut metadata = match extra_metadata {
            Some(serde_json::Value::Object(object)) => object,
            _ => serde_json::Map::new(),
        };
        if let Some(runtime) = metadata
            .entry("chio_runtime")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
            .as_object_mut()
        {
            runtime.insert(
                crate::kernel::runtime_field::RETRYABLE_AFTER_RESUME.into(),
                serde_json::Value::Bool(true),
            );
        }
        self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            Some(serde_json::Value::Object(metadata)),
            "kernel",
        )
    }

    /// Persist a signed local deny receipt for an RSS/allocation load-shed.
    ///
    /// The shed is checked on the same pre-negotiation fast path as the
    /// emergency stop, which already records a signed deny receipt. Recording
    /// one here keeps overload denials inside the same receipt-totality audit
    /// trail every other admission decision has, and makes the `OverloadResource`
    /// actually appear in a receipt deny reason as `error.rs` documents. The
    /// caller still returns [`KernelError::Overloaded`] so the
    /// tower load-shed edge surfaces backpressure; this only records evidence and
    /// never changes the error. A receipt-persist failure is surfaced to the
    /// caller, which logs it without masking the shed decision (fail-closed).
    pub(crate) fn record_overload_shed_deny_receipt(
        &self,
        request: &ToolCallRequest,
        resource: crate::OverloadResource,
        timestamp: u64,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<(), KernelError> {
        let reason =
            format!("kernel shed load to stay within its memory budget (resource: {resource:?})");
        // Local, non-federated v1 deny receipt: the shed runs before receipt
        // negotiation and peer pinning, exactly like the emergency-stop path.
        let _response = self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            &reason,
            timestamp,
            None,
            extra_metadata,
            "kernel.overload",
        )?;
        Ok(())
    }

    /// Build a Deny response for pre-dispatch receipt persistence admission.
    /// Federated dispatches require a durable local receipt store before any
    /// tool side effect, even when the negotiated receipt version is v1.
    pub(crate) fn build_receipt_persistence_failclosed_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            "kernel.receipt_persistence",
        )
    }

    pub(crate) fn build_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            None,
            ReceiptRecordMode::WithFederation,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    pub(crate) fn build_deny_response_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            verified_payee_binding,
            ReceiptRecordMode::WithFederation,
        )
    }

    pub(crate) fn build_runtime_admission_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            None,
            ReceiptRecordMode::LocalOnly,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    fn build_deny_response_with_recording(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
        record_mode: ReceiptRecordMode,
    ) -> Result<ToolCallResponse, KernelError> {
        let prepared = self.prepare_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            verified_payee_binding,
            record_mode,
        )?;
        self.publish_prepared_response(request, prepared)
    }

    pub(in crate::kernel) fn prepare_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
    ) -> Result<PreparedResponse, KernelError> {
        self.prepare_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            None,
            ReceiptRecordMode::WithFederation,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Preparation preserves the existing response input contract."
    )]
    pub(in crate::kernel) fn prepare_deny_response_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<PreparedResponse, KernelError> {
        self.prepare_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            verified_payee_binding,
            ReceiptRecordMode::WithFederation,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Preparation preserves the existing response input contract."
    )]
    fn prepare_deny_response_with_recording(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: RefusalReceiptMetadata,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
        record_mode: ReceiptRecordMode,
    ) -> Result<PreparedResponse, KernelError> {
        let extra_metadata =
            self.prepare_refusal_receipt_metadata(&request.request_id, extra_metadata)?;
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
            verified_payee_binding,
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index)?,
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        Ok(PreparedResponse::terminal(
            ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output: None,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Completed,
                receipt,
                execution_nonce: None,
            },
            record_mode,
        ))
    }
}
