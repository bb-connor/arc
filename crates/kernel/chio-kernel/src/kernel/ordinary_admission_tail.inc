impl ChioKernel {
    pub(super) fn ordinary_budget_charge(
        &self,
        grant_index: usize,
        grant: &ToolGrant,
        hold_id: &str,
        authorized: &AuthorizedBudgetHold,
        admission_operation: BudgetAdmissionOperationBinding,
    ) -> Option<BudgetChargeResult> {
        let (cost_charged, currency) = self.ordinary_payment_charge_terms(grant)?;
        Some(BudgetChargeResult {
            grant_index,
            cost_charged,
            currency,
            budget_total: grant
                .max_total_cost
                .as_ref()
                .map_or(u64::MAX, |amount| amount.units),
            new_committed_cost_units: authorized.committed_cost_units_after,
            budget_hold_id: hold_id.to_string(),
            authorize_metadata: authorized.metadata.clone(),
            admission_operation: Some(admission_operation),
        })
    }

    pub(super) fn ordinary_payment_charge_terms(&self, grant: &ToolGrant) -> Option<(u64, String)> {
        let has_monetary =
            grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();
        has_monetary.then(|| {
            (
                grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map_or(0, |amount| amount.units),
                grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|amount| amount.currency.clone())
                    .or_else(|| {
                        grant
                            .max_total_cost
                            .as_ref()
                            .map(|amount| amount.currency.clone())
                    })
                    .unwrap_or_else(|| "USD".to_string()),
            )
        })
    }

    pub(super) fn commit_ordinary_protocol_dispatch(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<serde_json::Value, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::InlineDispatch,
        )? {
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(metadata) => Ok(metadata),
            OrdinaryProtocolCaptureOutcome::CallerReservation(_) => Err(KernelError::Internal(
                "ordinary dispatch returned a caller reservation capture".to_string(),
            )),
        }
    }

    pub(super) fn commit_threshold_protocol_dispatch(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<serde_json::Value, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::ThresholdDispatch,
        )? {
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(metadata) => Ok(metadata),
            OrdinaryProtocolCaptureOutcome::CallerReservation(_) => Err(KernelError::Internal(
                "threshold dispatch returned a caller reservation capture".to_string(),
            )),
        }
    }

    /// Capture an operation-owned composite admission for a caller-mediated
    /// execution. The caller must keep the exact hold stamped and the signed
    /// execution nonce private until this returns: `CallerReserved` is the
    /// durable handoff boundary after which startup recovery may not compensate
    /// the captured invocation reservations.
    pub(super) fn commit_ordinary_protocol_caller_reservation(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<CallerReservationCaptureOutcome, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::CallerReservationOrdinary,
        )? {
            OrdinaryProtocolCaptureOutcome::CallerReservation(capture) => Ok(capture),
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(_) => Err(KernelError::Internal(
                "ordinary caller reservation returned dispatch metadata".to_string(),
            )),
        }
    }

    pub(super) fn commit_threshold_protocol_caller_reservation(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<CallerReservationCaptureOutcome, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::CallerReservationThreshold,
        )? {
            OrdinaryProtocolCaptureOutcome::CallerReservation(capture) => Ok(capture),
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(_) => Err(KernelError::Internal(
                "threshold caller reservation returned dispatch metadata".to_string(),
            )),
        }
    }

    fn commit_protocol_capture(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        mode: OrdinaryProtocolCaptureMode,
    ) -> Result<OrdinaryProtocolCaptureOutcome, KernelError> {
        let mut operation = self.load_ordinary_admission(mutation.operation_id())?;
        if operation.state() == AdmissionOperationState::BudgetAuthorized {
            operation = self.ordinary_admission_transition(
                &operation,
                AdmissionOperationState::ReadyToDispatch,
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }
        if operation.state() == AdmissionOperationState::ReadyToDispatch {
            if mutation.supplemental && mode.prepares_supplemental_dispatch() {
                let registrar =
                    self.supplemental_admission_registrar
                        .as_ref()
                        .ok_or_else(|| {
                            KernelError::Internal(
                                "supplemental admission registrar disappeared before dispatch"
                                    .to_string(),
                            )
                        })?;
                if let Err(error) = registrar.prepare_dispatch(operation.operation_id()) {
                    self.reverse_ordinary_protocol_admission(cap, mutation)?;
                    return Err(KernelError::GuardDenied(error.to_string()));
                }
            }
            operation = self.ordinary_admission_transition(
                &operation,
                mode.pending_state(),
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }
        if operation.state() != mode.pending_state() {
            return Err(KernelError::GuardDenied(format!(
                "admission operation {} cannot capture from {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        if matches!(
            mode,
            OrdinaryProtocolCaptureMode::CallerReservationOrdinary
                | OrdinaryProtocolCaptureMode::CallerReservationThreshold
        ) && operation.approval_set_hash().is_some()
        {
            if let Err(error) = self.commit_threshold_approval(operation.operation_id()) {
                self.reverse_ordinary_protocol_admission_from_capture_pending(
                    cap,
                    mutation,
                    &error.to_string(),
                )?;
                return Err(error);
            }
            self.discharge_admission_cleanup_action(
                &operation,
                crate::security_admission_operation::AdmissionCleanupActionKind::Approval,
            )?;
        }
        if mode.commits_presented_replay_reservations() {
            let replay_commit = self
                .commit_admission_execution_nonce(&operation)
                .and_then(|()| {
                    if operation.execution_nonce_id().is_some() {
                        self.discharge_admission_cleanup_action(
                            &operation,
                            crate::security_admission_operation::AdmissionCleanupActionKind::ExecutionNonce,
                        )?;
                    }
                    Ok(())
                });
            if let Err(error) = replay_commit {
                self.reverse_ordinary_protocol_admission_from_capture_pending(
                    cap,
                    mutation,
                    &error.to_string(),
                )?;
                return Err(error);
            }
        }
        let capture_request = BudgetCaptureInvocationRequest {
            capability_id: cap.id.clone(),
            grant_index: mutation.grant_index,
            hold_id: Some(mutation.hold_id.clone()),
            event_id: Some(mutation.capture_event_id.clone()),
            authority: mutation.authorized.metadata.authority.clone(),
            admission_operation: Some(BudgetAdmissionOperationBinding::new(
                mutation.operation_id.clone(),
                mutation.request_binding_hash.clone(),
            )?),
        };
        let capture_metadata = if !mutation.authorization_artifact_digests.is_empty() {
            let revocation_set = mutation.authorized.revocation_set.clone().ok_or_else(|| {
                KernelError::Internal("supplemental hold omitted its revocation set".to_string())
            })?;
            let request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
                operation_id: operation.operation_id().to_string(),
                budget: capture_request,
                revocation_set: revocation_set.clone(),
                bound_revocation_set_digest: revocation_set.digest().to_string(),
                authorization_artifact_digests: mutation.authorization_artifact_digests.clone(),
                aggregate_root_capability_id: mutation.aggregate_root_capability_id.clone(),
                aggregate_root_binding_digest: mutation.aggregate_binding_digest.clone(),
                last_observed_revocation_index: None,
            })?;
            let authority = self.admission_capture_authority.as_ref().ok_or_else(|| {
                KernelError::Internal("admission capture authority is unavailable".to_string())
            })?;
            let decision = authority
                .query_admission_capture(&request)
                .and_then(|existing| match existing {
                    Some(decision) => Ok(decision),
                    None => authority.capture_admission(request.clone()),
                })
                .map_err(|error| KernelError::BudgetCaptureRecoveryRequired(error.to_string()))?;
            match decision {
                AdmissionCaptureDecision::Captured { budget, metadata } => {
                    if budget.invocation_state != BudgetInvocationReservationState::Captured {
                        return Err(KernelError::BudgetCaptureRecoveryRequired(
                            "combined authority did not capture invocation reservations"
                                .to_string(),
                        ));
                    }
                    if let Err(error) = self.validate_hard_budget_commit_metadata(
                        &budget.metadata,
                        &mutation.capture_event_id,
                        mutation.authorized.metadata.authority.as_ref(),
                        mutation.authorized.metadata.budget_commit_index,
                        "combined capture",
                    ) {
                        // Captured reservations cannot be reversed truthfully.
                        // Leave the durable operation in its capture-pending
                        // state so an exact retry can re-query and validate
                        // without a second effect.
                        return Err(KernelError::BudgetCaptureRecoveryRequired(
                            error.to_string(),
                        ));
                    }
                    if metadata.checked_revocation_set_digest() != revocation_set.digest()
                        || metadata.aggregate_root_capability_id()
                            != mutation.aggregate_root_capability_id.as_deref()
                        || metadata.aggregate_root_binding_digest()
                            != mutation.aggregate_binding_digest.as_deref()
                    {
                        return Err(KernelError::BudgetCaptureRecoveryRequired(
                            "combined capture metadata does not match the verified admission evidence"
                                .to_string(),
                        ));
                    }
                    let projection = CombinedAdmissionCaptureReceiptProjection::from_capture(
                        &request,
                        &mutation.authorized,
                        &budget,
                        &metadata,
                    )?;
                    serde_json::to_value(projection).map_err(|error| {
                        KernelError::Internal(format!(
                            "authoritative admission capture projection serialization failed: {error}"
                        ))
                    })?
                }
                AdmissionCaptureDecision::Denied(denial) => {
                    validate_capture_denial_partition_escrow_evidence(
                        &mutation.authorized,
                        &denial,
                        "combined capture denial",
                    )?;
                    self.reverse_ordinary_protocol_admission_from_capture_pending(
                        cap,
                        mutation,
                        "capture authority definitively denied admission",
                    )?;
                    return Err(KernelError::CapabilityRevoked(
                        denial.revoked_ids().join(","),
                    ));
                }
            }
        } else {
            let captured = self
                .with_budget_store(|store| {
                    store
                        .capture_invocation_reservations(capture_request.clone())
                        .or_else(|_| store.capture_invocation_reservations(capture_request))
                        .map_err(KernelError::from)
                })
                .map_err(|error| KernelError::BudgetCaptureRecoveryRequired(error.to_string()))?;
            if captured.invocation_state != BudgetInvocationReservationState::Captured {
                return Err(KernelError::BudgetCaptureRecoveryRequired(
                    "budget authority did not capture invocation reservations".to_string(),
                ));
            }
            if let Err(error) = self.validate_hard_budget_commit_metadata(
                &captured.metadata,
                &mutation.capture_event_id,
                mutation.authorized.metadata.authority.as_ref(),
                mutation.authorized.metadata.budget_commit_index,
                "capture",
            ) {
                // Captured reservations cannot be reversed truthfully. Keep
                // the mode-specific pending state for idempotent authority
                // recovery.
                return Err(KernelError::BudgetCaptureRecoveryRequired(
                    error.to_string(),
                ));
            }
            let projection = BudgetInvocationCaptureReceiptProjection::from_capture(
                operation.operation_id(),
                &mutation.authorized,
                &captured,
            )?;
            serde_json::to_value(projection).map_err(|error| {
                KernelError::Internal(format!(
                    "budget invocation capture projection serialization failed: {error}"
                ))
            })?
        };
        match mode {
            OrdinaryProtocolCaptureMode::InlineDispatch => {
                operation = self.commit_tool_dispatch_once(&operation)?.ok_or_else(|| {
                    KernelError::GovernedTransactionDenied(format!(
                        "{} admission operation {} was committed by another coordinator",
                        mode.label(),
                        operation.operation_id()
                    ))
                })?;
            }
            OrdinaryProtocolCaptureMode::ThresholdDispatch => {}
            OrdinaryProtocolCaptureMode::CallerReservationOrdinary
            | OrdinaryProtocolCaptureMode::CallerReservationThreshold => {
                let reserved = operation.transition_checked(
                    AdmissionOperationState::CallerReserved,
                    AdmissionDispatchState::Committed,
                    operation.coordinator_lease_epoch(),
                    None,
                )?;
                return Ok(OrdinaryProtocolCaptureOutcome::CallerReservation(
                    CallerReservationCaptureOutcome {
                        current: operation,
                        reserved,
                        capture_metadata,
                    },
                ));
            }
        }
        Ok(OrdinaryProtocolCaptureOutcome::DispatchMetadata(
            self.ordinary_admission_receipt_metadata(mutation, &operation, capture_metadata),
        ))
    }

    pub(super) fn bind_threshold_dispatch_receipt_operation(
        &self,
        mutation: &OrdinaryAdmissionMutation,
        operation: &AdmissionOperation,
        capture_receipt: &serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        let capture = capture_receipt
            .pointer("/protocol_admission/invocation_capture")
            .cloned()
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold capture receipt omitted invocation metadata".to_string(),
                )
            })?;
        Ok(self.ordinary_admission_receipt_metadata(mutation, operation, capture))
    }

    pub(crate) fn reverse_ordinary_protocol_admission(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        self.reverse_ordinary_protocol_admission_inner(cap, mutation, None, None)
    }

    pub(super) fn reverse_ordinary_protocol_admission_with_authority(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        cleanup_authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        self.reverse_ordinary_protocol_admission_inner(cap, mutation, cleanup_authority, None)
    }

    pub(super) fn reverse_ordinary_protocol_admission_from_capture_pending(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        reason: &str,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        self.reverse_ordinary_protocol_admission_inner(cap, mutation, None, Some(reason))
    }

    fn reverse_ordinary_protocol_admission_inner(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        cleanup_authority: Option<&crate::budget_store::BudgetEventAuthority>,
        capture_pending_compensation_reason: Option<&str>,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        let claim = if let Some(reason) = capture_pending_compensation_reason {
            self.claim_capture_pending_compensation(mutation.operation_id(), reason)
        } else {
            self.claim_pre_dispatch_compensation(
                mutation.operation_id(),
                "pre-dispatch admission reversed",
            )
        }?;
        let operation = claim.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "admission operation {} cannot reverse after capture began or dispatch committed",
                mutation.operation_id()
            ))
        })?;
        let reversed = self.with_budget_store(|store| {
            let mut trusted_authorization_metadata = mutation.authorized.metadata.clone();
            if let Some(cleanup_authority) = cleanup_authority {
                trusted_authorization_metadata.authority = Some(cleanup_authority.clone());
            }
            let request = BudgetReverseHoldRequest {
                capability_id: cap.id.clone(),
                grant_index: mutation.grant_index,
                reversed_exposure_units: mutation
                    .charge_result()
                    .map_or(0, |charge| charge.cost_charged),
                hold_id: Some(mutation.hold_id.clone()),
                event_id: Some(mutation.reverse_event_id.clone()),
                authority: cleanup_authority
                    .cloned()
                    .or_else(|| mutation.authorized.metadata.authority.clone()),
                admission_operation: Some(BudgetAdmissionOperationBinding::new(
                    mutation.operation_id.clone(),
                    mutation.request_binding_hash.clone(),
                )?),
            };
            let expected_authority = request.authority.clone();
            let reversed = store
                .reverse_budget_hold(request.clone())
                .or_else(|_| store.reverse_budget_hold(request))
                .map_err(KernelError::from)?;
            let expected_monetary_state = match mutation.authorized.monetary_state {
                BudgetMonetaryHoldState::Exposed => BudgetMonetaryHoldState::Reversed,
                BudgetMonetaryHoldState::None => BudgetMonetaryHoldState::None,
                _ => {
                    return Err(KernelError::GuardDenied(
                        "operation-owned reverse started from a non-reversible monetary state"
                            .to_string(),
                    ));
                }
            };
            self.validate_budget_terminal_decision_for_store(
                store,
                &reversed,
                BudgetTerminalDecisionExpectation {
                    authorization_metadata: &trusted_authorization_metadata,
                    expected_event_id: &mutation.reverse_event_id,
                    expected_authority: expected_authority.as_ref(),
                    expected_capability_id: Some(&cap.id),
                    expected_grant_index: mutation.grant_index,
                    expected_hold_id: &mutation.hold_id,
                    expected_admission_operation: Some(mutation.admission_operation()),
                    expected_mutation_kind: BudgetMutationKind::ReverseInvocations,
                    expected_exposure_units: mutation
                        .charge_result()
                        .map_or(0, |charge| charge.cost_charged),
                    expected_realized_spend_units: 0,
                    expected_invocation_state: BudgetInvocationReservationState::Reversed,
                    expected_monetary_state,
                    stage: "operation-owned reverse",
                },
            )?;
            Ok(reversed)
        })?;
        if operation.approval_set_hash().is_some() {
            self.cancel_threshold_approval_if_reserved(operation.operation_id())?;
        }
        if operation.execution_nonce_id().is_some() {
            self.cancel_admission_nonce_if_reserved(operation.operation_id())?;
        }
        if mutation.supplemental {
            if let Some(registrar) = self.supplemental_admission_registrar.as_ref() {
                registrar
                    .release_admission(mutation.operation_id())
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
        }
        Ok(reversed)
    }

    pub(super) fn ordinary_admission_receipt_metadata(
        &self,
        mutation: &OrdinaryAdmissionMutation,
        operation: &AdmissionOperation,
        capture: serde_json::Value,
    ) -> serde_json::Value {
        let quotas: Vec<serde_json::Value> = mutation
            .authorized
            .invocation_counts_after
            .iter()
            .map(|usage| {
                serde_json::json!({
                    "profile": usage.quota.key().profile().as_str(),
                    "owner_id": usage.quota.key().owner_id(),
                    "grant_index": usage.quota.key().grant_index(),
                    "max_invocations": usage.quota.max_invocations(),
                    "reserved_invocations_after": usage.reserved_invocations_after,
                    "captured_invocations_after": usage.captured_invocations_after,
                })
            })
            .collect();
        serde_json::json!({
            "protocol_admission": {
                "hold_id": mutation.hold_id,
                "request_binding_hash": mutation.request_binding_hash,
                "guarantee_level": mutation.authorized.metadata.guarantee_level.as_str(),
                "authority_profile": mutation.authorized.metadata.budget_profile.as_str(),
                "metering_profile": mutation.authorized.metadata.metering_profile.as_str(),
                "aggregate_family_preservation": mutation
                    .aggregate_binding_digest
                    .as_ref()
                    .zip(mutation.aggregate_root_capability_id.as_ref())
                    .map(|(root_binding_digest, root_capability_id)| serde_json::json!({
                        "root_capability_id": root_capability_id,
                        "root_binding_digest": root_binding_digest,
                    })),
                "supplemental_verifier_id": mutation.supplemental_verifier_id,
                "supplemental_request_binding_hash": mutation
                    .supplemental_request_binding_hash,
                "supplemental_negotiated_features_digest": mutation
                    .supplemental_negotiated_features_digest,
                "authorize": {
                    "event_id": mutation.authorized.metadata.event_id,
                    "budget_commit_index": mutation.authorized.metadata.budget_commit_index,
                    "invocation_state": mutation.authorized.invocation_state.as_str(),
                    "monetary_state": mutation.authorized.monetary_state.as_str(),
                    "invocation_quotas": quotas,
                    "revocation_set_digest": mutation
                        .authorized
                        .revocation_set
                        .as_ref()
                        .map(crate::supplemental_quota::CanonicalRevocationSet::digest),
                    "authorization_artifact_digests": mutation.authorization_artifact_digests,
                },
                "invocation_capture": capture,
                "admission_operation": {
                    "operation_id": operation.operation_id(),
                    "state": operation.state().as_str(),
                    "dispatch_state": operation.dispatch_state().as_str(),
                    "version": operation.version(),
                }
            }
        })
    }

    pub(super) fn ordinary_admission_operation_metadata(
        &self,
        operation: &AdmissionOperation,
    ) -> serde_json::Value {
        serde_json::json!({
            "protocol_admission": {
                "admission_operation": {
                    "operation_id": operation.operation_id(),
                    "state": operation.state().as_str(),
                    "dispatch_state": operation.dispatch_state().as_str(),
                    "version": operation.version(),
                    "last_error": operation.last_error(),
                }
            }
        })
    }

    pub(super) fn validate_hard_budget_commit_metadata(
        &self,
        metadata: &BudgetCommitMetadata,
        expected_event_id: &str,
        expected_authority: Option<&crate::budget_store::BudgetEventAuthority>,
        prior_commit_index: Option<u64>,
        stage: &str,
    ) -> Result<(), KernelError> {
        self.with_budget_store(|store| {
            self.validate_hard_budget_commit_metadata_for_store(
                store,
                metadata,
                expected_event_id,
                expected_authority,
                prior_commit_index,
                stage,
            )
        })
    }

    pub(super) fn validate_hard_budget_commit_metadata_for_store(
        &self,
        store: &dyn crate::budget_store::BudgetStore,
        metadata: &BudgetCommitMetadata,
        expected_event_id: &str,
        expected_authority: Option<&crate::budget_store::BudgetEventAuthority>,
        prior_commit_index: Option<u64>,
        stage: &str,
    ) -> Result<(), KernelError> {
        let store_profile = store.authority_profile();
        let configured_guarantee = store.budget_guarantee_level();
        let configured_authority_profile = store.budget_authority_profile();
        let configured_metering_profile = store.budget_metering_profile();
        let partition_escrow_is_valid =
            if metadata.guarantee_level == BudgetGuaranteeLevel::PartitionEscrowed {
                let Some(registry) = self.partition_escrow_registry.as_deref() else {
                    return Err(KernelError::GuardDenied(format!(
                        "{stage} partition escrow authority is not configured"
                    )));
                };
                let Some(commit_evidence) = metadata.partition_escrow_evidence.as_ref() else {
                    return Err(KernelError::GuardDenied(format!(
                        "{stage} partition escrow commit omitted signed allocation evidence"
                    )));
                };
                let Some(binding) = store.partition_escrow_store_binding()? else {
                    return Err(KernelError::GuardDenied(format!(
                        "{stage} partition escrow store omitted its sealed counter binding"
                    )));
                };
                commit_evidence.validate_store_binding(&binding).is_ok()
                    && commit_evidence.evidence().is_ok_and(|evidence| {
                        registry.verify_persisted_admission(&evidence).is_ok()
                    })
            } else {
                metadata.partition_escrow_evidence.is_none()
                    && self.partition_escrow_registry.is_none()
                    && store.partition_escrow_store_binding()?.is_none()
            };
        let authority_is_valid = match metadata.guarantee_level {
            BudgetGuaranteeLevel::SingleNodeAtomic => {
                metadata.authority.as_ref() == expected_authority
            }
            BudgetGuaranteeLevel::HaLinearizable => {
                metadata.authority.as_ref().is_some_and(|authority| {
                    !authority.authority_id.is_empty()
                        && !authority.lease_id.is_empty()
                        && authority.lease_epoch > 0
                        && (prior_commit_index.is_none()
                            || metadata.authority.as_ref() == expected_authority)
                })
            }
            BudgetGuaranteeLevel::PartitionEscrowed => {
                partition_escrow_is_valid
                    && metadata.authority.as_ref().is_some_and(|authority| {
                        !authority.authority_id.is_empty()
                            && !authority.lease_id.is_empty()
                            && authority.lease_epoch > 0
                            && (prior_commit_index.is_none()
                                || metadata.authority.as_ref() == expected_authority)
                    })
            }
            BudgetGuaranteeLevel::AdvisoryPosthoc => false,
        };
        let supports_hard_limit =
            if metadata.guarantee_level == BudgetGuaranteeLevel::PartitionEscrowed {
                store_profile == crate::budget_store::BudgetStoreProfile::SharedLinearizable
                    && partition_escrow_is_valid
            } else {
                metadata
                    .guarantee_level
                    .supports_hard_invocation_limit(store_profile, self.dispatch_worker_count)
            };
        if metadata.guarantee_level != configured_guarantee
            || metadata.budget_profile != configured_authority_profile
            || metadata.metering_profile != configured_metering_profile
            || !supports_hard_limit
            || metadata.event_id.as_deref() != Some(expected_event_id)
            || !authority_is_valid
        {
            return Err(KernelError::GuardDenied(format!(
                "{stage} budget commit metadata cannot enforce the configured hard budget ceiling"
            )));
        }
        if metadata.authority.is_none()
            || metadata
                .budget_commit_index
                .is_none_or(|commit_index| commit_index == 0)
        {
            return Err(KernelError::GuardDenied(format!(
                "{stage} hard budget commit omitted fenced authority evidence"
            )));
        }
        if let (Some(previous), Some(current)) = (prior_commit_index, metadata.budget_commit_index)
        {
            if current <= previous {
                return Err(KernelError::GuardDenied(format!(
                    "{stage} budget commit index did not advance"
                )));
            }
        } else if prior_commit_index.is_some() {
            return Err(KernelError::GuardDenied(format!(
                "{stage} hard budget commit omitted its monotonic commit index"
            )));
        }
        Ok(())
    }

    pub(super) fn validate_budget_terminal_decision_for_store(
        &self,
        store: &dyn crate::budget_store::BudgetStore,
        decision: &BudgetHoldMutationDecision,
        expected: BudgetTerminalDecisionExpectation<'_>,
    ) -> Result<(), KernelError> {
        let prior_commit_index = expected
            .authorization_metadata
            .budget_commit_index
            .filter(|commit_index| *commit_index > 0)
            .ok_or_else(|| {
                KernelError::GuardDenied(format!(
                    "{} authorization omitted its hard budget commit index",
                    expected.stage
                ))
            })?;
        if expected.authorization_metadata.authority.as_ref() != expected.expected_authority {
            return Err(KernelError::GuardDenied(format!(
                "{} changed the prior budget authority",
                expected.stage
            )));
        }
        self.validate_hard_budget_commit_metadata_for_store(
            store,
            &decision.metadata,
            expected.expected_event_id,
            expected.expected_authority,
            Some(prior_commit_index),
            expected.stage,
        )?;
        if decision.metadata.guarantee_level != expected.authorization_metadata.guarantee_level
            || decision.metadata.budget_profile != expected.authorization_metadata.budget_profile
            || decision.metadata.metering_profile
                != expected.authorization_metadata.metering_profile
            || decision.metadata.partition_escrow_evidence
                != expected.authorization_metadata.partition_escrow_evidence
            || decision.hold_id.as_deref() != Some(expected.expected_hold_id)
            || decision.exposure_units != expected.expected_exposure_units
            || decision.realized_spend_units != expected.expected_realized_spend_units
            || decision.invocation_state != expected.expected_invocation_state
            || decision.monetary_state != expected.expected_monetary_state
        {
            return Err(KernelError::GuardDenied(format!(
                "{} budget terminal decision does not match its authorized hold",
                expected.stage
            )));
        }
        let mutation = store
            .get_mutation_event_by_id(expected.expected_event_id)?
            .ok_or_else(|| {
                KernelError::GuardDenied(format!(
                    "{} durable budget mutation event is unavailable",
                    expected.stage
                ))
            })?;
        let expected_grant_index = u32::try_from(expected.expected_grant_index).map_err(|_| {
            KernelError::GuardDenied(format!(
                "{} expected budget grant index exceeds u32",
                expected.stage
            ))
        })?;
        let committed_cost_units_after = mutation
            .total_cost_exposed_after
            .checked_add(mutation.total_cost_realized_spend_after)
            .ok_or_else(|| {
                KernelError::GuardDenied(format!(
                    "{} durable budget mutation committed cost overflowed u64",
                    expected.stage
                ))
            })?;
        if mutation.event_id != expected.expected_event_id
            || mutation.hold_id.as_deref() != Some(expected.expected_hold_id)
            || expected
                .expected_capability_id
                .is_some_and(|capability_id| mutation.capability_id.as_str() != capability_id)
            || mutation.grant_index != expected_grant_index
            || mutation.admission_operation.as_ref() != expected.expected_admission_operation
            || mutation.kind != expected.expected_mutation_kind
            || mutation.allowed.is_some()
            || decision.metadata.budget_commit_index != Some(mutation.event_seq)
            || mutation.usage_seq != Some(mutation.event_seq)
            || mutation.authority.as_ref() != expected.expected_authority
            || mutation.exposure_units != decision.exposure_units
            || mutation.realized_spend_units != decision.realized_spend_units
            || mutation.max_invocations.is_some()
            || mutation.max_cost_per_invocation.is_some()
            || mutation.max_total_cost_units.is_some()
            || mutation.invocation_count_after != decision.invocation_count_after
            || mutation.invocation_counts_after != decision.invocation_counts_after
            || mutation.invocation_state != decision.invocation_state
            || mutation.monetary_state != decision.monetary_state
            || mutation.revocation_set != decision.revocation_set
            || committed_cost_units_after != decision.committed_cost_units_after
        {
            return Err(KernelError::GuardDenied(format!(
                "{} durable budget mutation event does not match the terminal decision",
                expected.stage
            )));
        }
        Ok(())
    }

    pub(super) fn validate_budget_authorization_decision_for_store(
        &self,
        store: &dyn crate::budget_store::BudgetStore,
        request: &BudgetAuthorizeHoldRequest,
        decision: &BudgetAuthorizeHoldDecision,
        authorization_artifact_digests: &[String],
        stage: &str,
    ) -> Result<(), KernelError> {
        let admission_evidence = request.invocation_admission_evidence().ok_or_else(|| {
            KernelError::GuardDenied(format!(
                "{stage} authorization request omitted verified admission evidence"
            ))
        })?;
        let expected_artifact_digests =
            admission_authorization_artifact_digests(admission_evidence)?;
        if authorization_artifact_digests != expected_artifact_digests {
            return Err(KernelError::GuardDenied(format!(
                "{stage} authorization artifact digests do not match verified admission evidence"
            )));
        }
        let expected_partition_escrow_evidence =
            authorization_partition_escrow_commit_evidence(request, stage)?;
        let (
            allowed,
            decision_hold_id,
            decision_exposure_units,
            decision_committed_cost_units_after,
            decision_invocation_count_after,
            decision_invocation_counts_after,
            decision_invocation_state,
            decision_monetary_state,
            decision_revocation_set,
            metadata,
        ) = match decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => (
                true,
                authorized.hold_id.as_deref(),
                authorized.authorized_exposure_units,
                authorized.committed_cost_units_after,
                authorized.invocation_count_after,
                authorized.invocation_counts_after.as_slice(),
                authorized.invocation_state,
                authorized.monetary_state,
                authorized.revocation_set.as_ref(),
                &authorized.metadata,
            ),
            BudgetAuthorizeHoldDecision::Denied(denied) => (
                false,
                denied.hold_id.as_deref(),
                denied.attempted_exposure_units,
                denied.committed_cost_units_after,
                denied.invocation_count_after,
                denied.invocation_counts_after.as_slice(),
                denied.invocation_state,
                denied.monetary_state,
                denied.revocation_set.as_ref(),
                &denied.metadata,
            ),
        };
        let expected_event_id = request.event_id.as_deref().ok_or_else(|| {
            KernelError::GuardDenied(format!(
                "{stage} authorization request omitted its durable event id"
            ))
        })?;
        if metadata.partition_escrow_evidence != expected_partition_escrow_evidence {
            return Err(KernelError::GuardDenied(format!(
                "{stage} partition escrow commit does not match verified admission evidence"
            )));
        }
        self.validate_hard_budget_commit_metadata_for_store(
            store,
            metadata,
            expected_event_id,
            request.authority.as_ref(),
            None,
            stage,
        )?;
        let mutation = store
            .get_mutation_event_by_id(expected_event_id)?
            .ok_or_else(|| {
                KernelError::GuardDenied(format!(
                    "{stage} durable budget authorization event is unavailable"
                ))
            })?;
        for usage in &mutation.invocation_counts_after {
            usage.validate()?;
        }
        let expected_grant_index = u32::try_from(request.grant_index).map_err(|_| {
            KernelError::GuardDenied(format!("{stage} expected budget grant index exceeds u32"))
        })?;
        let expected_mutation_kind = BudgetMutationKind::ReserveInvocations;
        let expected_invocation_state = if allowed {
            BudgetInvocationReservationState::Authorized
        } else {
            BudgetInvocationReservationState::Denied
        };
        let monetary_present = request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some();
        let expected_monetary_state = if allowed && monetary_present {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let committed_cost_units_after = mutation
            .total_cost_exposed_after
            .checked_add(mutation.total_cost_realized_spend_after)
            .ok_or_else(|| {
                KernelError::GuardDenied(format!(
                    "{stage} durable budget authorization committed cost overflowed u64"
                ))
            })?;
        let quotas_match = mutation.invocation_counts_after.len()
            == request.invocation_quotas().len()
            && mutation
                .invocation_counts_after
                .iter()
                .zip(request.invocation_quotas())
                .all(|(usage, quota)| &usage.quota == quota);
        let expected_primary_quota_key =
            BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_invocation_count_after = mutation
            .invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &expected_primary_quota_key)
            .ok_or_else(|| {
                KernelError::GuardDenied(format!(
                    "{stage} durable budget authorization omitted its primary grant quota"
                ))
            })?
            .invocation_count_after()?;
        if mutation.event_id != expected_event_id
            || mutation.hold_id != request.hold_id
            || mutation.capability_id != request.capability_id
            || mutation.grant_index != expected_grant_index
            || mutation.admission_operation != request.admission_operation
            || mutation.kind != expected_mutation_kind
            || mutation.allowed != Some(allowed)
            || metadata.budget_commit_index != Some(mutation.event_seq)
            || mutation.usage_seq != allowed.then_some(mutation.event_seq)
            || mutation.authority != metadata.authority
            || mutation.exposure_units != request.requested_exposure_units
            || mutation.realized_spend_units != 0
            || mutation.max_invocations != request.max_invocations
            || mutation.max_cost_per_invocation != request.max_cost_per_invocation
            || mutation.max_total_cost_units != request.max_total_cost_units
            || !quotas_match
            || mutation.invocation_count_after != primary_invocation_count_after
            || mutation.invocation_state != expected_invocation_state
            || mutation.monetary_state != expected_monetary_state
            || mutation.revocation_set.as_ref() != request.revocation_set()
            || decision_hold_id != request.hold_id.as_deref()
            || decision_exposure_units != request.requested_exposure_units
            || decision_committed_cost_units_after != committed_cost_units_after
            || decision_invocation_count_after != mutation.invocation_count_after
            || decision_invocation_counts_after != mutation.invocation_counts_after.as_slice()
            || decision_invocation_state != mutation.invocation_state
            || decision_monetary_state != mutation.monetary_state
            || decision_revocation_set != mutation.revocation_set.as_ref()
        {
            return Err(KernelError::GuardDenied(format!(
                "{stage} budget authorization decision does not match its durable event"
            )));
        }
        Ok(())
    }

    pub(super) fn load_ordinary_admission(
        &self,
        operation_id: &str,
    ) -> Result<AdmissionOperation, KernelError> {
        self.admission_operation_store
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal("admission operation store is unavailable".to_string())
            })?
            .load(operation_id)?
            .ok_or_else(|| {
                KernelError::Internal(format!("admission operation {operation_id} disappeared"))
            })
    }

    fn ordinary_admission_transition(
        &self,
        operation: &AdmissionOperation,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        last_error: Option<String>,
    ) -> Result<AdmissionOperation, KernelError> {
        if next_state.is_terminal() {
            return Err(KernelError::Internal(
                "terminal ordinary admission transitions require an atomic signed receipt outbox"
                    .to_string(),
            ));
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("admission operation store is unavailable".to_string())
        })?;
        match store.compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch: ORDINARY_COORDINATOR_LEASE_EPOCH
                .max(operation.coordinator_lease_epoch()),
            last_error,
        }) {
            Ok(AdmissionOperationCasOutcome::Applied(next)) => Ok(next),
            Ok(AdmissionOperationCasOutcome::Conflict(current))
                if current.state() == next_state =>
            {
                Ok(current)
            }
            Ok(AdmissionOperationCasOutcome::Conflict(current)) => {
                Err(KernelError::Internal(format!(
                    "admission transition conflicted at {}",
                    current.state().as_str()
                )))
            }
            Ok(AdmissionOperationCasOutcome::Missing) => Err(KernelError::Internal(
                "admission operation disappeared during transition".to_string(),
            )),
            Err(error) => match store.load(operation.operation_id()) {
                Ok(Some(current)) if current.state() == next_state => Ok(current),
                _ => Err(KernelError::Internal(format!(
                    "admission transition acknowledgement is uncertain: {error}"
                ))),
            },
        }
    }

    /// Win or recover the durable compensation branch before mutating any
    /// participant. The dispatch CAS and this CAS share the same operation
    /// version, so exactly one terminal direction can become authoritative.
    /// A durable compensated record is safe to resume because every downstream
    /// release is operation-bound and idempotent.
    pub(super) fn claim_pre_dispatch_compensation(
        &self,
        operation_id: &str,
        reason: &str,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        self.claim_pre_dispatch_compensation_inner(operation_id, reason, false)
    }

    fn claim_capture_pending_compensation(
        &self,
        operation_id: &str,
        reason: &str,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        self.claim_pre_dispatch_compensation_inner(operation_id, reason, true)
    }

    fn claim_pre_dispatch_compensation_inner(
        &self,
        operation_id: &str,
        reason: &str,
        capture_cannot_have_committed: bool,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("admission operation store is unavailable".to_string())
        })?;
        let current = store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!("admission operation {operation_id} disappeared"))
        })?;
        if matches!(
            current.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            if !self.recover_compensated_admission_operation(current.operation_id())? {
                return Err(KernelError::Internal(format!(
                    "admission operation {} has cleanup owned by another recovery worker",
                    current.operation_id()
                )));
            }
            let terminal = store.load(current.operation_id())?.ok_or_else(|| {
                KernelError::Internal(
                    "admission operation disappeared after compensation recovery".to_string(),
                )
            })?;
            return Ok(Some(terminal));
        }
        // Both capture-pending states are uncertainty boundaries. A capture
        // may already be committed while its acknowledgement is in flight, so
        // generic cleanup cannot claim either one. Only a caller that has not
        // entered the capture authority yet, or an exact authority-returned
        // Denied decision, may cross this boundary into compensation.
        if matches!(
            current.state(),
            AdmissionOperationState::CapturePending
                | AdmissionOperationState::CallerReservationCapturePending
        ) && !capture_cannot_have_committed
        {
            return Ok(None);
        }
        if current.dispatch_state() != AdmissionDispatchState::NotStarted
            || matches!(
                current.state(),
                AdmissionOperationState::DispatchCommitted
                    | AdmissionOperationState::CallerReserved
                    | AdmissionOperationState::Completed
                    | AdmissionOperationState::OutcomeUnknownAfterDispatch
            )
        {
            return Ok(None);
        }
        let current = self.stage_compensation_pending_with_terminal_receipt(
            store.as_ref(),
            &current,
            reason,
        )?;
        if !self.recover_compensated_admission_operation(current.operation_id())? {
            return Err(KernelError::Internal(format!(
                "admission operation {} has cleanup owned by another recovery worker",
                current.operation_id()
            )));
        }
        let terminal = store.load(current.operation_id())?.ok_or_else(|| {
            KernelError::Internal(
                "admission operation disappeared after compensation terminalization".to_string(),
            )
        })?;
        Ok(Some(terminal))
    }
}
