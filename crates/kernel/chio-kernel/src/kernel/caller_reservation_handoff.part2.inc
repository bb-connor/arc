impl ChioKernel {
    fn recover_caller_reservation_handoff_for_probe(
        &self,
        operation: &AdmissionOperation,
        request: &ToolCallRequest,
        caller_receipt_metadata: Option<&serde_json::Value>,
        now: u64,
    ) -> Result<CallerReservationReplayProbe, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let intent_action = exact_handoff_action(
            store.as_ref(),
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        match self.validate_handoff_intent(
            operation,
            &intent,
            Some(request),
            caller_receipt_metadata,
            false,
            now,
        ) {
            Ok(()) => {}
            Err(KernelError::GuardDenied(_)) => return Ok(CallerReservationReplayProbe::Conflict),
            Err(error) => return Err(error),
        }
        self.recover_caller_reservation_capture_pending_handoff(
            store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            operation,
        )?;
        let Some(current) = store.load(operation.operation_id())? else {
            return Err(KernelError::Internal(
                "caller reservation operation disappeared after exact recovery".to_string(),
            ));
        };
        if current.state() != AdmissionOperationState::CallerReserved {
            return Ok(CallerReservationReplayProbe::Conflict);
        }
        let final_action = exact_handoff_action(
            store.as_ref(),
            current.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoff,
        )?;
        let payload = parse_handoff_payload(&final_action)?;
        if i64::try_from(now).unwrap_or(i64::MAX) >= payload.expires_at
            || !self.caller_reservation_handoff_hold_is_live(&current, &intent, &payload)?
        {
            return Ok(CallerReservationReplayProbe::Conflict);
        }
        match self.finalize_caller_reservation_handoff_delivery(
            &current,
            &intent_action,
            &final_action,
            now,
        ) {
            Ok(response) => Ok(CallerReservationReplayProbe::Replayed(response)),
            Err(KernelError::GuardDenied(_)) => Ok(CallerReservationReplayProbe::Conflict),
            Err(error) => Err(error),
        }
    }

    fn caller_reservation_payment_projection(
        &self,
        operation: &AdmissionOperation,
        intent: &SignedCallerReservationHandoffIntent,
    ) -> Result<CallerReservationPaymentProjection, KernelError> {
        let (hold, journal) = self.with_budget_store(|store| {
            Ok((
                store.get_budget_hold(&intent.body.hold_id)?,
                store.get_payment_journal(&intent.body.request_id)?,
            ))
        })?;
        let hold = hold.ok_or_else(|| {
            KernelError::Internal(
                "caller reservation handoff lost its exact durable hold".to_string(),
            )
        })?;
        if !hold.disposition.is_open()
            || hold.hold_id != intent.body.hold_id
            || hold.capability_id != intent.body.capability_id
            || hold.grant_index != intent.body.matched_grant_index
            || hold.reserved_until != Some(intent.body.expires_at)
        {
            return Err(KernelError::Internal(
                "caller reservation handoff hold changed its exact reserved binding".to_string(),
            ));
        }
        if let Some(record) = journal.as_ref() {
            let binding = BudgetAdmissionOperationBinding::new(
                operation.operation_id().to_string(),
                operation.request_binding_hash().to_string(),
            )?;
            if record.request_id != intent.body.request_id
                || record.capability_id != intent.body.capability_id
                || usize::try_from(record.grant_index).ok() != Some(intent.body.matched_grant_index)
                || record.admission_operation.as_ref() != Some(&binding)
                || record.hold_id.as_deref() != Some(intent.body.hold_id.as_str())
                || record.tenant_id != intent.body.trusted_tenant_id
            {
                return Err(KernelError::Internal(
                    "caller reservation payment journal changed its operation binding".to_string(),
                ));
            }
        }
        if intent.body.requires_settled_prepayment {
            let record = journal.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation settled prepayment has no durable payment journal"
                        .to_string(),
                )
            })?;
            let transaction_id = record.transaction_id.as_deref().ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation settled prepayment has no exact transaction".to_string(),
                )
            })?;
            if record.state != PaymentJournalState::Settled
                || transaction_id.is_empty()
                || hold.reserved_payment_reference.as_deref() != Some(transaction_id)
            {
                return Err(KernelError::Internal(
                    "caller reservation payment journal is not an exact settled prepayment"
                        .to_string(),
                ));
            }
        } else if hold.reserved_payment_reference.is_some() || journal.is_some() {
            return Err(KernelError::Internal(
                "caller reservation without prepayment acquired payment state".to_string(),
            ));
        }
        Ok(CallerReservationPaymentProjection {
            required: intent.body.requires_settled_prepayment,
            hold_id: intent.body.hold_id.clone(),
            reserved_payment_reference: hold.reserved_payment_reference,
            journal,
        })
    }

    fn terminalize_expired_authoritative_caller_reservation(
        &self,
        operation: &AdmissionOperation,
        now: i64,
    ) -> Result<(), KernelError> {
        let hold_id = operation.budget_hold_id().ok_or_else(|| {
            KernelError::Internal(
                "expired caller reservation capture has no exact hold".to_string(),
            )
        })?;
        let _ = self.reap_expired_reserved_budget_holds(now)?;
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let current = operation_store
            .load(operation.operation_id())?
            .ok_or_else(|| {
                KernelError::Internal(
                    "expired caller reservation operation disappeared after global reap"
                        .to_string(),
                )
            })?;
        if current.state() == AdmissionOperationState::OutcomeUnknownAfterDispatch {
            self.validate_terminal_receipt_binding_with_store(operation_store.as_ref(), &current)?;
            return Ok(());
        }
        if !matches!(
            (current.state(), current.dispatch_state()),
            (
                AdmissionOperationState::CallerReservationCapturePending,
                AdmissionDispatchState::NotStarted
            ) | (
                AdmissionOperationState::CallerReserved,
                AdmissionDispatchState::Committed
            )
        ) || current.version() != operation.version()
        {
            return Err(KernelError::Internal(
                "expired caller reservation changed state without a terminal receipt".to_string(),
            ));
        }
        let hold = self
            .with_budget_store(|store| Ok(store.get_budget_hold(hold_id)?))?
            .ok_or_else(|| {
                KernelError::Internal(
                    "expired caller reservation capture lost its exact hold".to_string(),
                )
            })?;
        if hold.disposition != BudgetHoldDispositionView::Expired {
            return Err(KernelError::Internal(
                "authoritative caller capture expired without a fail-closed hold forfeit"
                    .to_string(),
            ));
        }
        self.release_reserved_sibling_share_for_hold(hold_id);
        self.finalize_caller_reservation_outcome_unknown(
            &current,
            "caller reservation capture expired before exact handoff publication",
            Some(serde_json::json!({
                "caller_reservation_recovery": {
                    "hold_id": hold_id,
                    "hold_disposition": hold.disposition.as_str(),
                    "forfeited_exposure_units": hold.authorized_exposure_units,
                }
            })),
        )?;
        Ok(())
    }

    fn require_caller_reservation_response_still_live(
        &self,
        operation: &AdmissionOperation,
        expires_at: i64,
    ) -> Result<(), KernelError> {
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        if now < expires_at {
            return Ok(());
        }
        self.terminalize_expired_authoritative_caller_reservation(operation, now)?;
        Err(KernelError::GuardDenied(
            "caller reservation expired during exact handoff delivery".to_string(),
        ))
    }

    fn build_final_handoff_response(
        &self,
        reserved: &AdmissionOperation,
        intent: &SignedCallerReservationHandoffIntent,
        capture_metadata: serde_json::Value,
        payment: &CallerReservationPaymentProjection,
    ) -> Result<ToolCallResponse, KernelError> {
        if self.public_key() != intent.body.signer_identity
            || self.config.policy_hash != intent.body.policy_hash
        {
            return Err(KernelError::ReceiptSigningFailed(
                "caller reservation handoff signer or policy changed before final response"
                    .to_string(),
            ));
        }
        let protocol_metadata = finalize_protocol_admission_metadata(
            intent.body.protocol_admission_base.clone(),
            capture_metadata,
            reserved,
        )?;
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    intent.body.base_receipt_metadata.clone(),
                    Some(protocol_metadata),
                ),
                Some(serde_json::json!({
                    "caller_reservation_payment": payment,
                })),
            ),
            Some(serde_json::json!({
                "receipt_context": { "request_id": intent.body.request_id }
            })),
        );
        let receipt_content = receipt_content_for_output(None, None)?;
        if receipt_content.content_hash != intent.body.content_hash {
            return Err(KernelError::ReceiptSigningFailed(
                "caller reservation handoff content preimage changed before final signing"
                    .to_string(),
            ));
        }
        crate::kernel::responses::require_earned_mediated_trust_level(
            metadata.as_ref(),
            chio_core::receipt::kinds::TrustLevel::Mediated,
        )?;
        let body = chio_core::receipt::body::ChioReceiptBody {
            id: intent.body.receipt_id.clone(),
            timestamp: intent.body.timestamp,
            capability_id: intent.body.capability_id.clone(),
            tool_server: intent.body.tool_server.clone(),
            tool_name: intent.body.tool_name.clone(),
            action: intent.body.action.clone(),
            decision: Some(Decision::Incomplete {
                reason: intent.body.incomplete_reason.clone(),
            }),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: intent.body.content_hash.clone(),
            policy_hash: intent.body.policy_hash.clone(),
            evidence: intent.body.guard_evidence.clone(),
            metadata,
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: intent.body.trusted_tenant_id.clone(),
            kernel_key: intent.body.signer_identity.clone(),
            bbs_projection_version: None,
        };
        let receipt = crate::sign_receipt_body_with_backend(
            body,
            self.authority_signing_backend.as_ref(),
            &receipt_content.canonical_content,
        )?;
        if receipt.algorithm != Some(receipt.signature.algorithm())
            || receipt.kernel_key.algorithm() != receipt.signature.algorithm()
        {
            return Err(KernelError::ReceiptSigningFailed(
                "caller reservation receipt algorithm does not match its embedded kernel key"
                    .to_string(),
            ));
        }
        if !receipt
            .verify_signature()
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
        {
            return Err(KernelError::ReceiptSigningFailed(
                "caller reservation final receipt signature did not verify".to_string(),
            ));
        }
        Ok(ToolCallResponse {
            request_id: intent.body.request_id.clone(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Incomplete {
                reason: intent.body.incomplete_reason.clone(),
            },
            receipt,
            execution_nonce: Some(Box::new(intent.body.execution_nonce.clone())),
        })
    }

    fn response_from_handoff_payload(
        &self,
        operation: &AdmissionOperation,
        intent_action: &AdmissionCleanupAction,
        intent: &SignedCallerReservationHandoffIntent,
        payload: &CallerReservationHandoffPayload,
        now: u64,
        require_unexpired: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        validate_final_handoff_payload(
            &self.public_key(),
            operation,
            intent_action,
            intent,
            payload,
            now,
            require_unexpired,
        )?;
        Ok(ToolCallResponse {
            request_id: payload.request_id.clone(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Incomplete {
                reason: payload.incomplete_reason.clone(),
            },
            receipt: payload.receipt.clone(),
            execution_nonce: Some(Box::new(payload.execution_nonce.clone())),
        })
    }

    fn finalize_caller_reservation_handoff_delivery(
        &self,
        operation: &AdmissionOperation,
        intent_action: &AdmissionCleanupAction,
        handoff_action: &AdmissionCleanupAction,
        now: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        let intent = parse_handoff_intent(intent_action)?;
        self.validate_handoff_intent(operation, &intent, None, None, false, now)?;
        let initial_payload = parse_handoff_payload(handoff_action)?;
        let initial_response = self.response_from_handoff_payload(
            operation,
            intent_action,
            &intent,
            &initial_payload,
            now,
            false,
        )?;
        self.require_caller_reservation_response_still_live(operation, initial_payload.expires_at)?;
        if !self.caller_reservation_handoff_hold_is_live(operation, &intent, &initial_payload)? {
            return Err(KernelError::GuardDenied(
                "caller reservation exact handoff is no longer live".to_string(),
            ));
        }
        if handoff_action.state() == AdmissionCleanupActionState::Completed {
            self.validate_caller_reservation_handoff_publication(
                &intent,
                &initial_response.receipt,
            )?;
            self.require_caller_reservation_response_still_live(
                operation,
                initial_payload.expires_at,
            )?;
            return Ok(initial_response);
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let now_unix_ms = now.saturating_mul(1_000);
        let claim_lease_ms = self.caller_reservation_delivery_claim_lease_ms(
            intent.body.federation_admission.remote_kernel_id.is_some(),
        )?;
        let claim_deadline_unix_ms = now_unix_ms.checked_add(claim_lease_ms).ok_or_else(|| {
            KernelError::Internal(
                "caller reservation delivery claim deadline overflowed u64".to_string(),
            )
        })?;
        let expires_at_unix_ms = u64::try_from(initial_payload.expires_at)
            .ok()
            .and_then(|expires_at| expires_at.checked_mul(1_000))
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation expiry cannot be represented in milliseconds".to_string(),
                )
            })?;
        if claim_deadline_unix_ms > expires_at_unix_ms {
            self.finalize_caller_reservation_outcome_unknown(
                operation,
                "caller reservation has insufficient lifetime for bounded exact handoff delivery",
                Some(serde_json::json!({
                    "caller_reservation_recovery": {
                        "expires_at": initial_payload.expires_at,
                        "required_delivery_deadline_unix_ms": claim_deadline_unix_ms,
                    }
                })),
            )?;
            return Err(KernelError::GuardDenied(
                "caller reservation has insufficient lifetime for bounded exact handoff delivery"
                    .to_string(),
            ));
        }
        let claim_token = uuid::Uuid::now_v7().to_string();
        let claimed = match store.claim_cleanup_action(
            handoff_action.action_id(),
            &claim_token,
            now_unix_ms,
            claim_deadline_unix_ms,
        )? {
            AdmissionCleanupActionClaimOutcome::Claimed(claimed) => claimed,
            AdmissionCleanupActionClaimOutcome::Completed(completed) => {
                let completed_payload = parse_handoff_payload(&completed)?;
                let completed_response = self.response_from_handoff_payload(
                    operation,
                    intent_action,
                    &intent,
                    &completed_payload,
                    now,
                    false,
                )?;
                self.validate_caller_reservation_handoff_publication(
                    &intent,
                    &completed_response.receipt,
                )?;
                self.require_caller_reservation_response_still_live(
                    operation,
                    completed_payload.expires_at,
                )?;
                return Ok(completed_response);
            }
            AdmissionCleanupActionClaimOutcome::Busy(_) => {
                return Err(KernelError::GuardDenied(
                    "caller reservation exact handoff delivery is already in progress".to_string(),
                ))
            }
            AdmissionCleanupActionClaimOutcome::Missing => {
                return Err(KernelError::Internal(
                    "caller reservation final handoff action disappeared".to_string(),
                ))
            }
        };
        if claimed.action_id() != handoff_action.action_id()
            || claimed.payload_hash() != handoff_action.payload_hash()
            || claimed.state() != AdmissionCleanupActionState::Claimed
        {
            return Err(KernelError::Internal(
                "caller reservation delivery claim changed its exact outbox".to_string(),
            ));
        }
        let payload = parse_handoff_payload(&claimed)?;
        let response = self.response_from_handoff_payload(
            operation,
            intent_action,
            &intent,
            &payload,
            now,
            false,
        )?;
        let _request_federation_scope = self.scope_receipt_federation_admission_for_request(
            &intent.body.request_id,
            intent.body.federation_admission.clone(),
        );
        let _thread_federation_scope =
            scope_receipt_federation_admission(Some(intent.body.federation_admission.clone()));
        if let Err(error) = self.publish_caller_reservation_handoff_receipt(
            &intent,
            &response.receipt,
            claimed.action_id(),
            claimed.version(),
            &claim_token,
        ) {
            let _ = store.abandon_cleanup_action(
                claimed.action_id(),
                claimed.version(),
                &claim_token,
                error.to_string(),
            );
            return Err(error);
        }
        match store.acknowledge_cleanup_action(claimed.action_id(), claimed.version(), &claim_token)
        {
            Ok(AdmissionCleanupActionCasOutcome::Applied(completed))
                if completed.state() == AdmissionCleanupActionState::Completed => {}
            Ok(AdmissionCleanupActionCasOutcome::Conflict(completed))
                if completed.state() == AdmissionCleanupActionState::Completed =>
            {
                self.validate_caller_reservation_handoff_publication(&intent, &response.receipt)?;
            }
            Ok(AdmissionCleanupActionCasOutcome::Applied(_))
            | Ok(AdmissionCleanupActionCasOutcome::Conflict(_)) => {
                return Err(KernelError::Internal(
                    "caller reservation delivery acknowledgement conflicted".to_string(),
                ))
            }
            Ok(AdmissionCleanupActionCasOutcome::Missing) => {
                return Err(KernelError::Internal(
                    "caller reservation delivery acknowledgement lost its outbox".to_string(),
                ))
            }
            Err(error) => {
                let completed = exact_handoff_action(
                    store.as_ref(),
                    operation.operation_id(),
                    AdmissionCleanupActionKind::CallerReservationHandoff,
                )?;
                if completed.state() != AdmissionCleanupActionState::Completed {
                    return Err(KernelError::Internal(format!(
                        "caller reservation delivery acknowledgement is uncertain: {error}"
                    )));
                }
                self.validate_caller_reservation_handoff_publication(&intent, &response.receipt)?;
            }
        }
        if !self.caller_reservation_handoff_hold_is_live(operation, &intent, &payload)? {
            return Err(KernelError::GuardDenied(
                "caller reservation closed during exact handoff delivery".to_string(),
            ));
        }
        self.require_caller_reservation_response_still_live(operation, payload.expires_at)?;
        Ok(response)
    }

    fn publish_caller_reservation_handoff_receipt(
        &self,
        intent: &SignedCallerReservationHandoffIntent,
        receipt: &ChioReceipt,
        action_id: &str,
        action_version: u64,
        claim_token: &str,
    ) -> Result<(), KernelError> {
        self.validate_caller_reservation_delivery_claim(
            &intent.body.operation_id,
            action_id,
            action_version,
            claim_token,
        )?;
        let receipt_store = self.receipt_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation handoff requires a durable receipt store".to_string(),
            )
        })?;
        if !receipt_store.supports_authoritative_chio_receipt_lookup() {
            return Err(KernelError::Internal(
                "caller reservation receipt store lacks authoritative point lookup".to_string(),
            ));
        }
        match receipt_store.load_chio_receipt(&receipt.id)? {
            Some(existing) => {
                if !canonical_serialized_values_equal(&existing, receipt)? {
                    return Err(KernelError::Internal(
                        "caller reservation receipt id resolved to conflicting durable content"
                            .to_string(),
                    ));
                }
            }
            None => self.record_chio_receipt_consuming_optional_intent(
                receipt,
                Some(&intent.body.request_id),
            )?,
        }
        let Some(remote_kernel_id) = intent.body.federation_admission.remote_kernel_id.as_deref()
        else {
            return Ok(());
        };
        let peer = intent
            .body
            .federation_admission
            .peer
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation federation delivery omitted its admitted peer".to_string(),
                )
            })?;
        let artifact_store = self
            .federation_artifact_store
            .as_ref()
            .filter(|store| store.is_durable() && store.supports_atomic_insert_or_equal())
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation federation delivery requires a durable artifact store"
                        .to_string(),
                )
            })?;
        let prior_dual = artifact_store.get_dual_signed(&receipt.id)?;
        let prior_dsse = artifact_store.get_dsse(&receipt.id)?;
        if let Some(dual) = prior_dual.as_ref() {
            validate_caller_reservation_dual_receipt(self, peer, receipt, dual)?;
        }
        if let Some(dsse) = prior_dsse.as_ref() {
            validate_caller_reservation_dsse(self, peer, receipt, dsse)?;
        }
        if prior_dual.is_some() && prior_dsse.is_some() {
            return Ok(());
        }
        let cosigner = self.federation_cosigner.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation federation delivery has no cosigner".to_string(),
            )
        })?;
        if !cosigner.supports_complete_receipt_cosigning_profile()
            || !cosigner.supports_idempotent_receipt_cosigning()
        {
            return Err(KernelError::Internal(
                "caller reservation federation cosigner lacks the complete exact-retry artifact profile"
                    .to_string(),
            ));
        }
        let local_kernel_id = self.federation_local_kernel_id();
        if prior_dual.is_none() {
            self.validate_caller_reservation_delivery_claim(
                &intent.body.operation_id,
                action_id,
                action_version,
                claim_token,
            )?;
            let dual = chio_federation::bilateral::co_sign_with_origin_backend(
                remote_kernel_id,
                &peer.public_key,
                &local_kernel_id,
                self.authority_signing_backend.as_ref(),
                receipt.clone(),
                cosigner.as_ref(),
            )
            .map_err(|error| {
                KernelError::Internal(format!(
                    "caller reservation bilateral receipt co-sign failed: {error}"
                ))
            })?;
            self.validate_caller_reservation_delivery_claim(
                &intent.body.operation_id,
                action_id,
                action_version,
                claim_token,
            )?;
            artifact_store.insert_dual_signed_if_absent_or_equal(&receipt.id, &dual)?;
        }
        if prior_dsse.is_none() {
            self.validate_caller_reservation_delivery_claim(
                &intent.body.operation_id,
                action_id,
                action_version,
                claim_token,
            )?;
            let treaty_material = intent
                .body
                .federation_admission
                .verified_treaty_material
                .as_ref()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "caller reservation federation receipt lacks verified treaty material"
                            .to_string(),
                    )
                })?;
            treaty_material.validate_cosign_participants(
                remote_kernel_id,
                &peer.public_key,
                &local_kernel_id,
                &self.config.keypair.public_key(),
            )?;
            let extensions = treaty_material.extensions_for_receipt_context(
                &intent.body.request_id,
                &intent.body.tool_server,
                &intent.body.tool_name,
                Some(remote_kernel_id),
                receipt,
            )?;
            let dsse = chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope_with_cosigner_backend(
                chio_federation::bilateral_dsse::BilateralDsseBackendCosigningInput {
                    invocation: chio_federation::bilateral_dsse::BilateralDsseInvocationInput {
                        receipt,
                        org_a_kernel_id: remote_kernel_id,
                        org_b_kernel_id: &local_kernel_id,
                        tool_name: &intent.body.tool_name,
                        timestamp_unix_ms: intent.body.timestamp.saturating_mul(1_000),
                        extensions,
                    },
                    org_a_public_key: &peer.public_key,
                    org_b_signer: self.authority_signing_backend.as_ref(),
                    org_a_cosigner: cosigner.as_ref(),
                },
            )
            .map_err(|error| {
                KernelError::Internal(format!(
                    "caller reservation bilateral DSSE co-sign failed: {error}"
                ))
            })?;
            self.validate_caller_reservation_delivery_claim(
                &intent.body.operation_id,
                action_id,
                action_version,
                claim_token,
            )?;
            artifact_store.insert_dsse_if_absent_or_equal(&receipt.id, &dsse)?;
        }
        let dual = artifact_store
            .get_dual_signed(&receipt.id)?
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation federation delivery omitted durable dual evidence"
                        .to_string(),
                )
            })?;
        let dsse = artifact_store.get_dsse(&receipt.id)?.ok_or_else(|| {
            KernelError::Internal(
                "caller reservation federation delivery omitted durable DSSE evidence".to_string(),
            )
        })?;
        validate_caller_reservation_dual_receipt(self, peer, receipt, &dual)?;
        validate_caller_reservation_dsse(self, peer, receipt, &dsse)?;
        Ok(())
    }

    fn validate_caller_reservation_delivery_claim(
        &self,
        operation_id: &str,
        action_id: &str,
        action_version: u64,
        claim_token: &str,
    ) -> Result<(), KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let current = exact_handoff_action(
            store.as_ref(),
            operation_id,
            AdmissionCleanupActionKind::CallerReservationHandoff,
        )?;
        let now_unix_ms = current_unix_timestamp().saturating_mul(1_000);
        if current.action_id() != action_id
            || current.state() != AdmissionCleanupActionState::Claimed
            || current.version() != action_version
            || current.claim_token() != Some(claim_token)
            || current
                .claim_deadline_unix_ms()
                .is_none_or(|deadline| deadline <= now_unix_ms)
        {
            return Err(KernelError::GuardDenied(
                "caller reservation delivery claim is no longer authoritative".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_caller_reservation_handoff_publication(
        &self,
        intent: &SignedCallerReservationHandoffIntent,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        let receipt_store = self.receipt_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "completed caller reservation lost its durable receipt store".to_string(),
            )
        })?;
        if !receipt_store.supports_authoritative_chio_receipt_lookup() {
            return Err(KernelError::Internal(
                "completed caller reservation receipt lookup is not authoritative".to_string(),
            ));
        }
        let stored = receipt_store
            .load_chio_receipt(&receipt.id)?
            .ok_or_else(|| {
                KernelError::Internal(
                    "completed caller reservation has no durable receipt publication".to_string(),
                )
            })?;
        if !canonical_serialized_values_equal(&stored, receipt)? {
            return Err(KernelError::Internal(
                "completed caller reservation durable receipt is conflicting".to_string(),
            ));
        }
        if intent.body.federation_admission.remote_kernel_id.is_none() {
            return Ok(());
        }
        let peer = intent
            .body
            .federation_admission
            .peer
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "completed caller reservation lost its admitted federation peer".to_string(),
                )
            })?;
        let artifact_store = self
            .federation_artifact_store
            .as_ref()
            .filter(|store| store.is_durable())
            .ok_or_else(|| {
                KernelError::Internal(
                    "completed caller reservation lost durable federation storage".to_string(),
                )
            })?;
        let dual = artifact_store
            .get_dual_signed(&receipt.id)?
            .ok_or_else(|| {
                KernelError::Internal(
                    "completed caller reservation lost durable dual evidence".to_string(),
                )
            })?;
        let dsse = artifact_store.get_dsse(&receipt.id)?.ok_or_else(|| {
            KernelError::Internal(
                "completed caller reservation lost durable DSSE evidence".to_string(),
            )
        })?;
        validate_caller_reservation_dual_receipt(self, peer, receipt, &dual)?;
        validate_caller_reservation_dsse(self, peer, receipt, &dsse)
    }

    pub(super) fn validate_caller_reserved_handoff_with_store(
        &self,
        store: &dyn crate::security_admission_operation::AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        self.validated_caller_reserved_handoff_receipt_with_store(store, operation)
            .map(|_| ())
    }

    pub(super) fn validated_caller_reserved_handoff_receipt_with_store(
        &self,
        store: &dyn crate::security_admission_operation::AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<ChioReceipt, KernelError> {
        let intent_action = exact_handoff_action(
            store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        self.validate_handoff_intent(operation, &intent, None, None, false, 0)?;
        let handoff_action = exact_handoff_action(
            store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoff,
        )?;
        let payload = parse_handoff_payload(&handoff_action)?;
        self.response_from_handoff_payload(operation, &intent_action, &intent, &payload, 0, false)
            .map(|response| response.receipt)
    }

    /// Recover publication of an already committed caller-reservation handoff
    /// from its signed request snapshot. No policy, budget, nonce, payment, or
    /// capture decision is recomputed here. A completed action is checked by
    /// authoritative point lookup only; a pending or expired claim resumes the
    /// exact durable receipt and federation artifact publication.
    pub(super) fn recover_caller_reserved_handoff_delivery_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        now: u64,
    ) -> Result<(), KernelError> {
        self.validate_caller_reserved_handoff_with_store(store, operation)?;
        let intent_action = exact_handoff_action(
            store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        let handoff_action = exact_handoff_action(
            store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoff,
        )?;
        if handoff_action.state() == AdmissionCleanupActionState::Completed {
            let payload = parse_handoff_payload(&handoff_action)?;
            let response = self.response_from_handoff_payload(
                operation,
                &intent_action,
                &intent,
                &payload,
                now,
                false,
            )?;
            return self
                .validate_caller_reservation_handoff_publication(&intent, &response.receipt);
        }
        self.finalize_caller_reservation_handoff_delivery(
            operation,
            &intent_action,
            &handoff_action,
            now,
        )
        .map(|_| ())
    }

    fn caller_reservation_handoff_hold_is_live(
        &self,
        operation: &AdmissionOperation,
        intent: &SignedCallerReservationHandoffIntent,
        payload: &CallerReservationHandoffPayload,
    ) -> Result<bool, KernelError> {
        let (hold, journal) = self.with_budget_store(|store| {
            Ok((
                store.get_budget_hold(&payload.hold_id)?,
                store.get_payment_journal(&payload.request_id)?,
            ))
        })?;
        let Some(hold) = hold else {
            return Ok(false);
        };
        let authorized = intent.body.authorization.to_authorized()?;
        if !hold.disposition.is_open() {
            return Ok(false);
        }
        if hold.hold_id != payload.hold_id
            || hold.capability_id != payload.capability_id
            || hold.grant_index != payload.matched_grant_index
            || authorized.hold_id.as_deref() != Some(hold.hold_id.as_str())
            || authorized.authorized_exposure_units != hold.authorized_exposure_units
            || hold.remaining_exposure_units != authorized.authorized_exposure_units
            || hold.authority != authorized.metadata.authority
            || hold.authorization_metadata != authorized.metadata
            || hold.reserved_until != Some(payload.expires_at)
            || hold.reserved_payment_reference != payload.payment.reserved_payment_reference
            || operation.budget_hold_id() != Some(payload.hold_id.as_str())
        {
            return Err(KernelError::Internal(
                "caller reservation live hold changed its exact handoff binding".to_string(),
            ));
        }
        if payload.payment.required {
            let frozen = payload.payment.journal.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation final handoff omitted settled payment evidence".to_string(),
                )
            })?;
            let Some(transaction_id) = payload.payment.reserved_payment_reference.as_deref() else {
                return Err(KernelError::Internal(
                    "caller reservation final handoff omitted its payment reference".to_string(),
                ));
            };
            if transaction_id.is_empty()
                || frozen.state != PaymentJournalState::Settled
                || frozen.transaction_id.as_deref() != Some(transaction_id)
                || hold.reserved_payment_reference.as_deref() != Some(transaction_id)
            {
                return Err(KernelError::Internal(
                    "caller reservation final handoff changed settled payment evidence".to_string(),
                ));
            }
            if journal.as_ref().is_some_and(|current| current != frozen) {
                return Ok(false);
            }
        } else if payload.payment.journal.is_some()
            || payload.payment.reserved_payment_reference.is_some()
            || journal.is_some()
        {
            return Err(KernelError::Internal(
                "caller reservation nonpayment handoff acquired payment evidence".to_string(),
            ));
        }
        if self
            .execution_nonce_store
            .as_deref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation replay prevention store is unavailable".to_string(),
                )
            })?
            .is_consumed(payload.execution_nonce.nonce_id())?
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn validate_handoff_intent(
        &self,
        operation: &AdmissionOperation,
        intent: &SignedCallerReservationHandoffIntent,
        request: Option<&ToolCallRequest>,
        caller_receipt_metadata: Option<&serde_json::Value>,
        require_unexpired: bool,
        now: u64,
    ) -> Result<(), KernelError> {
        let body = &intent.body;
        let nonce_timestamp = u64::try_from(body.execution_nonce.nonce.issued_at).ok();
        let expected_content_hash = receipt_content_for_output(None, None)?.content_hash;
        let current_signer = self.public_key();
        let expected_coordinator_authority_id = format!("kernel:{}", current_signer.to_hex());
        let federation_admission_matches = match (
            body.federation_admission.remote_kernel_id.as_deref(),
            body.federation_admission.peer.as_ref(),
        ) {
            (None, None) => true,
            (Some(remote), Some(peer)) => {
                peer.kernel_id == remote
                    && peer.established_at <= body.timestamp
                    && body.timestamp < peer.rotation_due
            }
            _ => false,
        };
        if body.schema != CALLER_RESERVATION_HANDOFF_INTENT_SCHEMA
            || body.operation_id != operation.operation_id()
            || body.request_binding_hash != operation.request_binding_hash()
            || body.request_id != operation.request_id()
            || body.capability_id != operation.capability_id()
            || body.authorization_capability_hash != operation.authorization_capability_hash()
            || body.hold_id.as_str() != operation.budget_hold_id().unwrap_or_default()
            || body.policy_hash != operation.policy_hash()
            || (operation.state() != AdmissionOperationState::CallerReserved
                && body.policy_hash != self.config.policy_hash)
            || body.signer_identity != current_signer
            || operation.coordinator_authority_id() != expected_coordinator_authority_id
            || !federation_admission_matches
            || body.authorization.hold_id != body.hold_id
            || body.content_hash != expected_content_hash
            || nonce_timestamp != Some(body.timestamp)
            || body.expires_at != body.execution_nonce.expires_at()
            || body.execution_nonce.reserved_hold_id() != Some(body.hold_id.as_str())
            || body.execution_nonce.reserving_request_id() != Some(body.request_id.as_str())
            || !body.action.verify_hash().map_err(|error| {
                KernelError::Internal(format!("caller reservation action hash failed: {error}"))
            })?
            || !is_supported_execution_nonce_schema(&body.execution_nonce.nonce.schema)
            || body.signer_identity.algorithm() != intent.signature.algorithm()
            || body.signer_identity.algorithm() != body.execution_nonce.signature.algorithm()
            || body.execution_nonce.nonce.bound_to.subject_id != body.capability_subject
            || body.execution_nonce.nonce.bound_to.capability_id != body.capability_id
            || body.execution_nonce.nonce.bound_to.tool_server != body.tool_server
            || body.execution_nonce.nonce.bound_to.tool_name != body.tool_name
            || body.execution_nonce.nonce.bound_to.parameter_hash != body.action.parameter_hash
        {
            return Err(KernelError::Internal(
                "caller reservation handoff intent changed an immutable binding".to_string(),
            ));
        }
        let envelope = CallerReservationHandoffIntentSigningEnvelope {
            domain: CALLER_RESERVATION_HANDOFF_INTENT_DOMAIN,
            body,
        };
        if !body
            .signer_identity
            .verify_canonical(&envelope, &intent.signature)
            .map_err(|error| KernelError::Internal(error.to_string()))?
        {
            return Err(KernelError::Internal(
                "caller reservation handoff intent signature is invalid".to_string(),
            ));
        }
        let nonce_bytes = chio_core::canonical::canonical_json_bytes(&body.execution_nonce.nonce)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        if !body
            .signer_identity
            .verify(&nonce_bytes, &body.execution_nonce.signature)
        {
            return Err(KernelError::Internal(
                "caller reservation execution nonce signature is invalid".to_string(),
            ));
        }
        let _ = body.authorization.to_authorized()?;
        if let Some(request) = request {
            let trusted_tenant_id = self
                .receipt_tenant_id_for_request(Some(&request.request_id))
                .unwrap_or_else(current_scoped_receipt_tenant_id);
            if !self.handoff_request_matches(
                operation,
                &body.request_fingerprint_hash,
                &body.request_snapshot_hash,
                request,
                caller_receipt_metadata,
            )? || body.tool_server != request.server_id
                || body.tool_name != request.tool_name
                || body.agent_id != request.agent_id
                || body.capability_subject != request.capability.subject.to_hex()
                || body.trusted_tenant_id != trusted_tenant_id
                || body.caller_receipt_metadata_hash
                    != canonical_optional_json_hash(caller_receipt_metadata)?
                || body.requires_settled_prepayment != Self::is_governed_mustprepay_request(request)
                || body.federation_admission.remote_kernel_id != request.federated_origin_kernel_id
                || body.execution_nonce.nonce.bound_to.parameter_hash != body.action.parameter_hash
            {
                return Err(KernelError::GuardDenied(
                    "caller reservation replay request does not match its durable handoff"
                        .to_string(),
                ));
            }
        }
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        if require_unexpired && now >= body.expires_at {
            return Err(KernelError::GuardDenied(
                "caller reservation handoff intent expired".to_string(),
            ));
        }
        Ok(())
    }

    fn handoff_request_matches(
        &self,
        operation: &AdmissionOperation,
        expected_fingerprint_hash: &str,
        expected_request_snapshot_hash: &str,
        request: &ToolCallRequest,
        caller_receipt_metadata: Option<&serde_json::Value>,
    ) -> Result<bool, KernelError> {
        let capability_hash =
            crate::threshold_approval::authorization_capability_hash(&request.capability)
                .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        if request.request_id != operation.request_id()
            || request.capability.id != operation.capability_id()
            || capability_hash != operation.authorization_capability_hash()
            || canonical_request_snapshot_hash(request)? != expected_request_snapshot_hash
        {
            return Ok(false);
        }
        if operation.approval_set_hash().is_none() {
            let supplemental_digest = request
                .supplemental_authorization
                .as_ref()
                .map(|authorization| {
                    OpaqueSignedSupplementalQuota::new(authorization.artifact().to_vec())
                        .map(|artifact| artifact.digest())
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))
                })
                .transpose()?;
            if self.ordinary_request_binding_hash_for_policy(
                request,
                operation.budget_hold_id().unwrap_or_default(),
                supplemental_digest.as_deref(),
                caller_receipt_metadata,
                operation.policy_hash(),
            )? != operation.request_binding_hash()
            {
                return Ok(false);
            }
        }
        Ok(self.ordinary_request_fingerprint_hash(
            request,
            operation.policy_hash(),
            caller_receipt_metadata,
        )? == expected_fingerprint_hash)
    }
}
