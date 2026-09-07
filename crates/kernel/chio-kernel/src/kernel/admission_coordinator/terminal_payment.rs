//! Payment settlement of a durable tool return: the journal disposition,
//! the rail settlement and its continuation after an interrupted attempt.

use super::*;

pub(super) struct DurablePaymentTerminal {
    pub(super) journal: crate::payment::PaymentJournalRecord,
    pub(super) reconcile: BudgetReconcileHoldDecision,
    pub(super) amount_units: u64,
}

pub(super) struct DurablePaymentSettlementInput<'a> {
    pub(super) admission: &'a DurableToolAdmission,
    pub(super) runtime: &'a DurableAdmissionRuntime,
    pub(super) lease: &'a crate::admission_operation::AdmissionRecoveryLease,
    pub(super) journal: crate::payment::PaymentJournalRecord,
    pub(super) disposition: &'a SettlementDispositionV1,
    pub(super) context: &'a AdmissionProjectionContext,
    pub(super) purchase: Option<&'a crate::finding_purchase::VerifiedFindingPurchase>,
    pub(super) trusted_now_unix_ms: u64,
}

fn payment_journal_matches_settlement(
    journal: &crate::payment::PaymentJournalRecord,
    action: crate::payment::PaymentSettleAction,
    amount_units: u64,
) -> bool {
    journal.settle_action == Some(action)
        && match action {
            crate::payment::PaymentSettleAction::Capture => {
                journal.settle_amount_units == Some(amount_units)
                    && journal.release_authority.is_none()
            }
            crate::payment::PaymentSettleAction::Release => {
                journal.settle_amount_units.is_none()
                    && journal.release_authority.as_ref().is_some_and(|authority| {
                        authority.kind
                            == crate::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge
                    })
            }
        }
}

impl ChioKernel {
    pub(super) fn durable_payment_disposition(
        &self,
        admission: &DurableToolAdmission,
        runtime: &DurableAdmissionRuntime,
        raw: &RawInvocationOutcomeV1,
        trusted_now_unix_ms: u64,
        delivery_denied: bool,
    ) -> Result<
        Option<(
            crate::payment::PaymentJournalRecord,
            SettlementDispositionV1,
        )>,
        KernelError,
    > {
        if !admission.requires_payment() {
            return Ok(None);
        }
        let journal = runtime
            .store
            .load_payment_journal(admission.operation_id(), &runtime.fence)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable payment participant disappeared during finalization".to_owned(),
                )
            })?;
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if journal.capability_id != admission.operation.binding().capability_id().as_str()
            || usize::try_from(journal.grant_index).ok()
                != Some(raw.matched_grant_index().map_err(tool_outcome_error)?)
        {
            return Err(KernelError::DurableAdmission(
                "payment journal does not match the recorded tool outcome".to_owned(),
            ));
        }
        let amount_units = match journal.rail_mode {
            crate::payment::PaymentRailMode::PrepaidFinal => journal.amount_units,
            crate::payment::PaymentRailMode::ReversibleHold => {
                let reported = raw.reported_cost();
                let units = match reported {
                    Some(cost) if cost.currency != journal.currency => {
                        let cost = ToolInvocationCost {
                            units: cost.units,
                            currency: cost.currency.clone(),
                            breakdown: None,
                        };
                        self.resolve_cross_currency_cost(
                            &cost,
                            &journal.currency,
                            trusted_now_unix_ms / 1_000,
                        )?
                        .0
                    }
                    Some(cost) => cost.units,
                    None => journal.amount_units,
                };
                if units > journal.amount_units {
                    return Err(KernelError::DurableAdmission(
                        "reported cost exceeds the durable payment authorization".to_owned(),
                    ));
                }
                units
            }
        };
        // A delivery mismatch releases the open hold and captures zero. The
        // pre-dispatch gate rejects every non-reversible rail for a
        // digest-constrained request, so a denied delivery is always a
        // reversible hold; assert that invariant rather than silently
        // producing an unreleasable zero-charge.
        if delivery_denied && journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold {
            return Err(KernelError::DurableAdmission(
                "delivery denial requires a reversible-hold rail".to_owned(),
            ));
        }
        let disposition = if delivery_denied || amount_units == 0 {
            SettlementDispositionV1::ContractualZeroCharge {
                currency: journal.currency.clone(),
            }
        } else {
            SettlementDispositionV1::Capture {
                amount: chio_core::capability::scope::MonetaryAmount {
                    units: amount_units,
                    currency: journal.currency.clone(),
                },
            }
        };
        Ok(Some((journal, disposition)))
    }

    fn continue_durable_payment_settlement(
        &self,
        operation: &AdmissionOperationV1,
        runtime: &DurableAdmissionRuntime,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        mut journal: crate::payment::PaymentJournalRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, KernelError> {
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if journal.operation_id != operation.binding().operation_id().as_str() {
            return Err(KernelError::DurableAdmission(
                "payment settlement changed operation identity".to_owned(),
            ));
        }
        if journal.state == crate::payment::PaymentJournalState::Settled {
            return Ok(Some(journal));
        }
        // A journal sealed as reconcile_failed still carries its settle action and
        // authorization, so the same intent is re-driven against the rail rather
        // than leaving the operation non-terminal with its hold already reconciled.
        if journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold
            || !matches!(
                journal.state,
                crate::payment::PaymentJournalState::Settling
                    | crate::payment::PaymentJournalState::ReconcileFailed
            )
        {
            return Err(KernelError::DurableAdmission(
                "payment journal has no replayable settlement intent".to_owned(),
            ));
        }
        let settle_action = journal.settle_action.ok_or_else(|| {
            KernelError::DurableAdmission("settling payment journal omitted its action".to_owned())
        })?;
        let authorization_id = journal.authorization_id.as_deref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "settling payment journal omitted authorization_id".to_owned(),
            )
        })?;
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "durable payment adapter disappeared during settlement".to_owned(),
            )
        })?;
        if adapter.rail_id() != journal.rail || adapter.rail_mode() != Some(journal.rail_mode) {
            return Err(KernelError::DurableAdmission(
                "durable payment adapter changed before settlement".to_owned(),
            ));
        }
        let result = match settle_action {
            crate::payment::PaymentSettleAction::Capture => adapter.capture(
                authorization_id,
                journal.settle_amount_units.ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "capture journal omitted its settlement amount".to_owned(),
                    )
                })?,
                &journal.currency,
                &journal.operation_id,
            ),
            crate::payment::PaymentSettleAction::Release => {
                adapter.release(authorization_id, &journal.operation_id)
            }
        }
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let compatible = matches!(
            (settle_action, result.settlement_status),
            (
                crate::payment::PaymentSettleAction::Capture,
                crate::payment::RailSettlementStatus::Captured
                    | crate::payment::RailSettlementStatus::Settled
            ) | (
                crate::payment::PaymentSettleAction::Release,
                crate::payment::RailSettlementStatus::Released
            )
        );
        if compatible {
            let transition = crate::payment::PaymentJournalTransition::SettlementCompleted {
                transaction_id: result.transaction_id,
            };
            journal = runtime
                .store
                .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation,
                    recovery_lease: lease,
                    expected: &journal,
                    transition: &transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                })
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            return Ok(Some(journal));
        }
        if result.settlement_status == crate::payment::RailSettlementStatus::Pending {
            return Ok(None);
        }
        if journal.state != crate::payment::PaymentJournalState::ReconcileFailed {
            let transition = crate::payment::PaymentJournalTransition::ReconcileFailed;
            runtime
                .store
                .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation,
                    recovery_lease: lease,
                    expected: &journal,
                    transition: &transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                })
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        }
        Err(KernelError::DurableAdmission(
            "payment rail returned an incompatible settlement status".to_owned(),
        ))
    }

    pub(super) fn settle_durable_payment(
        &self,
        input: DurablePaymentSettlementInput<'_>,
    ) -> Result<DurablePaymentTerminal, KernelError> {
        let DurablePaymentSettlementInput {
            admission,
            runtime,
            lease,
            mut journal,
            disposition,
            context,
            purchase,
            trusted_now_unix_ms,
        } = input;
        let (amount_units, settle_action) = match disposition {
            SettlementDispositionV1::Capture { amount } => {
                if amount.currency != journal.currency
                    || amount.units == 0
                    || amount.units > journal.amount_units
                {
                    return Err(KernelError::DurableAdmission(
                        "durable capture disposition conflicts with the payment journal".to_owned(),
                    ));
                }
                (amount.units, crate::payment::PaymentSettleAction::Capture)
            }
            SettlementDispositionV1::ContractualZeroCharge { currency } => {
                if currency != &journal.currency
                    || journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold
                {
                    return Err(KernelError::DurableAdmission(
                        "zero-charge disposition conflicts with the payment journal".to_owned(),
                    ));
                }
                (0, crate::payment::PaymentSettleAction::Release)
            }
            SettlementDispositionV1::NotApplicable => {
                return Err(KernelError::DurableAdmission(
                    "payment participant cannot use a not-applicable settlement".to_owned(),
                ));
            }
        };
        let hold_id = journal.hold_id.clone().ok_or_else(|| {
            KernelError::DurableAdmission("payment journal omitted its budget hold".to_owned())
        })?;
        let (transition, release_evidence) = match (journal.rail_mode, journal.state) {
            (
                crate::payment::PaymentRailMode::PrepaidFinal,
                crate::payment::PaymentJournalState::Settled,
            ) if journal.authorization_id.is_some() && amount_units == journal.amount_units => {
                (None, None)
            }
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                crate::payment::PaymentJournalState::Authorized,
            ) => match settle_action {
                crate::payment::PaymentSettleAction::Capture => (
                    Some(crate::payment::PaymentJournalTransition::BeginCapture { amount_units }),
                    None,
                ),
                crate::payment::PaymentSettleAction::Release => {
                    let proof = runtime
                        .verify_contractual_zero_charge(&admission.operation, context)
                        .map_err(tool_outcome_error)?;
                    let evidence =
                        crate::tool_outcome::MonetaryReleaseAuthority::ContractualZeroCharge(
                            Box::new(proof),
                        )
                        .evidence_bundle()
                        .map_err(tool_outcome_error)?;
                    let persisted = evidence.to_persisted();
                    let authority = crate::payment::PaymentReleaseAuthorityBinding {
                        kind: crate::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge,
                        operation_id: persisted.operation_id.as_str().to_owned(),
                        operation_version: persisted.operation_version,
                        evidence_id: persisted.evidence_id.as_str().to_owned(),
                        evidence_digest: persisted.bundle_digest.as_str().to_owned(),
                    };
                    (
                        Some(crate::payment::PaymentJournalTransition::BeginRelease { authority }),
                        Some(evidence),
                    )
                }
            },
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                crate::payment::PaymentJournalState::Settling
                | crate::payment::PaymentJournalState::Settled,
            ) if payment_journal_matches_settlement(&journal, settle_action, amount_units) => {
                (None, None)
            }
            (crate::payment::PaymentRailMode::PrepaidFinal, _) => {
                return Err(KernelError::DurableAdmission(
                    "final prepayment journal is not terminal and fixed-price".to_owned(),
                ));
            }
            (crate::payment::PaymentRailMode::ReversibleHold, _) => {
                return Err(KernelError::DurableAdmission(
                    "payment journal has no replayable settlement intent".to_owned(),
                ));
            }
        };
        let settlement = runtime
            .store
            .begin_payment_settlement(crate::receipt_store::AdmissionPaymentSettlementBegin {
                operation: &admission.operation,
                recovery_lease: lease,
                expected: &journal,
                transition: transition.as_ref(),
                release_evidence: release_evidence.as_ref(),
                budget_reconcile: BudgetReconcileHoldRequest {
                    capability_id: journal.capability_id.clone(),
                    grant_index: usize::try_from(journal.grant_index).map_err(|_| {
                        KernelError::DurableAdmission(
                            "payment journal grant index overflowed".to_owned(),
                        )
                    })?,
                    exposed_cost_units: journal.amount_units,
                    realized_spend_units: amount_units,
                    hold_id: Some(hold_id.clone()),
                    event_id: Some(format!("{hold_id}:reconcile")),
                    authority: Some(runtime.authority()),
                },
                active_fence: &runtime.fence,
                trusted_now_unix_ms,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        journal = settlement.journal;
        let reconcile = settlement.budget;
        if !payment_journal_matches_settlement(&journal, settle_action, amount_units) {
            return Err(KernelError::DurableAdmission(
                "payment journal conflicts with the pricing disposition".to_owned(),
            ));
        }
        if settle_action == crate::payment::PaymentSettleAction::Capture {
            if let Some(purchase) = purchase {
                let verifier = self.finding_purchase_verifier.as_ref().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "purchase capture lost its configured verifier".to_owned(),
                    )
                })?;
                verifier
                    .mark_capture_pending(purchase, trusted_now_unix_ms / 1_000)
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "purchase capture fence failed: {error}"
                        ))
                    })?;
            }
        }
        journal = self
            .continue_durable_payment_settlement(
                &admission.operation,
                runtime,
                lease,
                journal,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| {
                KernelError::DurableAdmission("payment settlement remains pending".to_owned())
            })?;
        if journal.state != crate::payment::PaymentJournalState::Settled {
            return Err(KernelError::DurableAdmission(
                "payment journal did not reach a terminal settlement".to_owned(),
            ));
        }
        Ok(DurablePaymentTerminal {
            journal,
            reconcile,
            amount_units,
        })
    }
}
