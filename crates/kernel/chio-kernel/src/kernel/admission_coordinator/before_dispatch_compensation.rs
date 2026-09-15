//! Durable compensation of pre-dispatch participants and payment exposure.
use super::*;

impl ChioKernel {
    pub(crate) fn compensate_durable_admission_before_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        verifier_policy: serde_json::Value,
        trusted_now_unix_ms: u64,
        confirmed_payment_unwind: Option<&PreDispatchPaymentUnwindEvidence>,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let current = runtime
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "pre-dispatch admission disappeared during compensation".to_owned(),
                )
            })?;
        if &current != operation
            || current.state().is_terminal()
            || current.dispatch_commit().is_some()
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch compensation operation changed".to_owned(),
            ));
        }
        let lease = self.claim_admission_recovery(&current, trusted_now_unix_ms)?;
        // Runtime replay custody must be physically released before any
        // compensation can assert no effect or unwind a monetary participant.
        self.release_retained_runtime_participants(&current, &lease, trusted_now_unix_ms)?;
        self.release_retained_governed_approval(&current, &lease, trusted_now_unix_ms)?;
        self.release_retained_dpop(&current, &lease, trusted_now_unix_ms)?;
        let context = AdmissionProjectionContext {
            operation_id: current.binding().operation_id().clone(),
            request_id: current.binding().request_id().clone(),
            expected_operation_version: current.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        if current
            .attachment(crate::admission_operation::AdmissionAttachmentKind::PaymentParticipant)
            .is_some()
        {
            let mut journal = runtime
                .store
                .load_payment_journal(current.binding().operation_id().as_str(), &runtime.fence)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "pre-dispatch payment journal disappeared".to_owned(),
                    )
                })?;
            if journal.state == crate::payment::PaymentJournalState::HoldPlaced {
                // The rail may have committed authorization before its reply
                // reached this journal. Only an authoritative negative can
                // cancel the original hold; uncertainty preserves exposure.
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "unacknowledged payment has no adapter".to_owned(),
                    )
                })?;
                if adapter.rail_id() != journal.rail
                    || adapter.rail_mode() != Some(journal.rail_mode)
                {
                    return Err(KernelError::DurableAdmission(
                        "payment recovery rail changed".to_owned(),
                    ));
                }
                let observed = run_payment_adapter_operation("settlement_state", || {
                    adapter.settlement_state(&journal.operation_id, None)
                })
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                let transition = match observed {
                    crate::payment::RailSettlementState::NoAuthorization => {
                        crate::payment::PaymentJournalTransition::CancelBeforeAuthorization
                    }
                    crate::payment::RailSettlementState::Held { authorization_id }
                        if journal.rail_mode == crate::payment::PaymentRailMode::ReversibleHold =>
                    {
                        validate_payment_adapter_identifier(
                            &authorization_id,
                            "recovered authorization identifier",
                        )
                        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                        crate::payment::PaymentJournalTransition::AuthorizationHeld {
                            authorization_id,
                        }
                    }
                    _ => {
                        return Err(KernelError::DurableAdmission(
                            "unacknowledged authorization has an incompatible rail outcome"
                                .to_owned(),
                        ))
                    }
                };
                journal = runtime
                    .store
                    .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                        operation: &current,
                        recovery_lease: &lease,
                        expected: &journal,
                        transition: &transition,
                        release_evidence: None,
                        active_fence: &runtime.fence,
                        trusted_now_unix_ms,
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            }
            if journal.state == crate::payment::PaymentJournalState::Authorized {
                // The rail hold was authorized before dispatch, so the tool never
                // ran and the authorization must be released rather than left held.
                // Drive the durable release the same way the live cleanup path does:
                // record the no-effect release authority, advance the journal to
                // Settling, release on the rail, then settle. The release proof is
                // built from the acquired-participant snapshot, which the terminal
                // compensation projection below also accepts.
                let proof =
                    crate::tool_outcome::VerifiedPreDispatchNoEffect::from_qualified_released_operation_snapshot(
                        &current,
                        &context,
                        verifier_policy.clone(),
                    )
                    .map_err(tool_outcome_error)?;
                let evidence = crate::tool_outcome::MonetaryReleaseAuthority::NoEffect(
                    crate::tool_outcome::VerifiedNoEffectProof::BeforeDispatch(proof),
                )
                .evidence_bundle()
                .map_err(tool_outcome_error)?;
                let persisted = evidence.to_persisted();
                let authority = crate::payment::PaymentReleaseAuthorityBinding {
                    kind: crate::payment::PaymentReleaseAuthorityKind::PreDispatchNoEffect,
                    operation_id: persisted.operation_id.as_str().to_owned(),
                    operation_version: persisted.operation_version,
                    evidence_id: persisted.evidence_id.as_str().to_owned(),
                    evidence_digest: persisted.bundle_digest.as_str().to_owned(),
                };
                journal = runtime
                    .store
                    .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                        operation: &current,
                        recovery_lease: &lease,
                        expected: &journal,
                        transition: &crate::payment::PaymentJournalTransition::BeginRelease {
                            authority,
                        },
                        release_evidence: Some(&evidence),
                        active_fence: &runtime.fence,
                        trusted_now_unix_ms,
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            }
            // Resume the same committed release intent after timeout or lost
            // acknowledgement. Its persisted authority remains the prerequisite
            // for settlement, including when a previous recovery staged it.
            if journal.state == crate::payment::PaymentJournalState::Settling
                && journal.settle_action == Some(crate::payment::PaymentSettleAction::Release)
            {
                journal
                    .validate()
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                let authorization_id = journal.authorization_id.clone().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "release journal omitted its authorization".to_owned(),
                    )
                })?;
                let transaction_id = if let Some(unwind) = confirmed_payment_unwind {
                    if unwind.authorization_id != authorization_id
                        || unwind.settlement_status
                            != crate::payment::PreDispatchPaymentUnwindStatus::Released
                    {
                        return Err(KernelError::DurableAdmission(
                            "confirmed pre-dispatch payment unwind does not match the journal"
                                .to_owned(),
                        ));
                    }
                    unwind.transaction_id.clone()
                } else {
                    let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "authorized pre-dispatch hold has no configured payment adapter"
                                .to_owned(),
                        )
                    })?;
                    if adapter.rail_id() != journal.rail
                        || adapter.rail_mode() != Some(journal.rail_mode)
                    {
                        return Err(KernelError::DurableAdmission(
                            "payment recovery rail changed".to_owned(),
                        ));
                    }
                    let result = run_payment_adapter_operation("release", || {
                        adapter.release(&authorization_id, &journal.operation_id)
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                    if result.settlement_status != crate::payment::RailSettlementStatus::Released {
                        return Err(KernelError::DurableAdmission(
                            "pre-dispatch rail release was not confirmed".to_owned(),
                        ));
                    }
                    validate_payment_adapter_identifier(
                        &result.transaction_id,
                        "recovered release transaction identifier",
                    )
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                    result.transaction_id
                };
                journal = runtime
                    .store
                    .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                        operation: &current,
                        recovery_lease: &lease,
                        expected: &journal,
                        transition:
                            &crate::payment::PaymentJournalTransition::SettlementCompleted {
                                transaction_id,
                            },
                        release_evidence: None,
                        active_fence: &runtime.fence,
                        trusted_now_unix_ms,
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            }
            let released = journal.state == crate::payment::PaymentJournalState::Settled
                && journal.settle_action == Some(crate::payment::PaymentSettleAction::Release);
            let cancelled_before_authorization = journal.state
                == crate::payment::PaymentJournalState::Closed
                && journal.authorization_id.is_none();
            if !released && !cancelled_before_authorization {
                return Err(KernelError::DurableAdmission(
                    "pre-dispatch payment release is not durable".to_owned(),
                ));
            }
        }
        self.release_finding_pool_claim_before_dispatch(
            current.binding().operation_id().as_str(),
            trusted_now_unix_ms,
        )
        .map_err(|error| {
            KernelError::DurableAdmission(format!(
                "pre-dispatch finding pool claim release failed: {error}"
            ))
        })?;
        // Every budget the operation still holds is internal until dispatch
        // commits. Both the executable hold and an owned preflight hold must be
        // physically reversed before the terminal projection can claim no effect.
        self.release_retained_executable_hold(&current)?;
        if let Some(preflight) = self.load_durable_nonce_preflight(&current, trusted_now_unix_ms)? {
            self.release_durable_nonce_preflight_hold(&current, &preflight)?;
        }
        let projection = verified_released_pre_dispatch_compensation_projection(
            &current,
            context,
            verifier_policy,
        )?;
        let terminal = runtime
            .store
            .commit_admission_projection(&projection)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if terminal.operation_id != *current.binding().operation_id()
            || terminal.state != AdmissionOperationState::CompensatedBeforeDispatch
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch compensation committed a different terminal operation".to_owned(),
            ));
        }
        Ok(())
    }
}
