//! Reconcile-by-nonce: the entry point where a mediated pre-execution
//! authorization becomes an authoritative spend.
//!
//! The mediated `/v1/evaluate` route reserves a durable budget hold at the
//! worst-case cost and mints a signed execution nonce bound to that hold
//! (`reserved_hold_id`). The caller executes the real tool downstream at a
//! server that shares the budget store, then presents the nonce back here with
//! the measured realized cost. This module settles the exact reserved hold at
//! that realized cost, releases the reserved-minus-realized difference back to
//! the grant, and signs a completed, authoritative mediated-spend receipt.
//!
//! It also exposes the reserved-hold TTL reaper: a wrapper that settles expired,
//! unreconciled reserved holds at their reserved worst-case (forfeit). The TTL
//! deadline itself is stamped from the minted nonce's exact expiry at reserve
//! time, so a hold never expires before its own nonce. Fail-closed on the money
//! path.

use chio_log_redact::redacted;

use super::ordinary_admission::BudgetTerminalDecisionExpectation;
use super::*;

use crate::budget_store::{
    BudgetHoldDispositionView, BudgetHoldSnapshot, BudgetInvocationReservationState,
    BudgetMonetaryHoldState, BudgetReconcileHoldRequest,
};
use crate::execution_nonce::{
    consume_execution_nonce, verify_execution_nonce_without_consume, SignedExecutionNonce,
};

/// Canonical inert currency stamped onto the signed receipt for a zero-exposure
/// invocation reconcile. Such a reserve carries no reserved currency, so its
/// realized currency is never validated (see step 3); using this fixed,
/// attacker-uncontrollable value keeps an unchecked caller-supplied string off
/// the signed artifact while still marking the receipt as carrying no monetary
/// envelope.
const INVOCATION_RECONCILE_RECEIPT_CURRENCY: &str = "";
const MAX_CALLER_RESERVATION_REAP_OPERATIONS: usize = 4_096;
const MAX_CALLER_RESERVATION_REAP_FAILURE_DETAILS: usize = 16;
const MAX_CALLER_RESERVATION_REAP_FAILURE_CHARS: usize = 512;

#[derive(Default)]
struct CallerReservationReapFailures {
    count: usize,
    details: Vec<String>,
}

impl CallerReservationReapFailures {
    fn push(&mut self, message: String) {
        self.count += 1;
        if self.details.len() < MAX_CALLER_RESERVATION_REAP_FAILURE_DETAILS {
            self.details.push(
                redacted!(&message)
                    .to_string()
                    .chars()
                    .take(MAX_CALLER_RESERVATION_REAP_FAILURE_CHARS)
                    .collect(),
            );
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn summary(&self) -> String {
        let omitted = self.count.saturating_sub(self.details.len());
        if omitted == 0 {
            format!("{} failures: {}", self.count, self.details.join("; "))
        } else {
            format!(
                "{} failures: {}; {omitted} additional failures omitted",
                self.count,
                self.details.join("; ")
            )
        }
    }
}

fn bounded_reap_error(error: &impl std::fmt::Display) -> String {
    redacted!(error)
        .to_string()
        .chars()
        .take(MAX_CALLER_RESERVATION_REAP_FAILURE_CHARS)
        .collect()
}

fn trusted_caller_reconciliation_metadata(
    handoff_receipt: &ChioReceipt,
    completion_metadata: &serde_json::Value,
    hold: &BudgetHoldSnapshot,
    presented_nonce: &SignedExecutionNonce,
    grant_index: u32,
) -> Result<serde_json::Value, KernelError> {
    let nonce_binding = &presented_nonce.nonce.bound_to;
    if handoff_receipt.capability_id != hold.capability_id
        || handoff_receipt.capability_id != nonce_binding.capability_id
        || handoff_receipt.tool_server != nonce_binding.tool_server
        || handoff_receipt.tool_name != nonce_binding.tool_name
        || handoff_receipt.action.parameter_hash != nonce_binding.parameter_hash
    {
        return Err(KernelError::Internal(
            "caller reservation handoff changed its reconcile receipt binding".to_string(),
        ));
    }

    let handoff_metadata = handoff_receipt.metadata.as_ref().ok_or_else(|| {
        KernelError::Internal(
            "caller reservation handoff omitted its frozen receipt metadata".to_string(),
        )
    })?;
    let attribution = handoff_metadata
        .get("attribution")
        .cloned()
        .ok_or_else(|| {
            KernelError::Internal(
                "caller reservation handoff omitted its signed attribution".to_string(),
            )
        })?;
    let attribution: ReceiptAttributionMetadata =
        serde_json::from_value(attribution).map_err(|_| {
            KernelError::Internal(
                "caller reservation handoff carried invalid signed attribution".to_string(),
            )
        })?;
    if attribution.subject_key != nonce_binding.subject_id
        || attribution.grant_index != Some(grant_index)
        || hold.reserved_delegation_depth != Some(attribution.delegation_depth)
        || hold.reserved_root_budget_holder.as_deref() != Some(attribution.issuer_key.as_str())
    {
        return Err(KernelError::Internal(
            "caller reservation handoff changed its reserved attribution".to_string(),
        ));
    }

    if hold.authorization_metadata.guarantee_level
        == crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed
    {
        let handoff_authority = handoff_receipt
            .financial_budget_authority_metadata()
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation handoff omitted its signed budget authority".to_string(),
                )
            })?;
        let handoff_partition = handoff_authority.partition_escrow.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation handoff omitted its signed partition allocation proof"
                    .to_string(),
            )
        })?;
        let hold_partition = hold
            .authorization_metadata
            .partition_escrow_evidence
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "reserved partition escrow hold omitted its allocation proof".to_string(),
                )
            })?;
        if handoff_authority.guarantee_level != hold.authorization_metadata.guarantee_level.as_str()
            || handoff_authority.authority_profile
                != hold.authorization_metadata.budget_profile.as_str()
            || handoff_authority.metering_profile
                != hold.authorization_metadata.metering_profile.as_str()
            || handoff_authority.hold_id != hold.hold_id
            || handoff_authority.authorize.event_id != hold.authorization_metadata.event_id
            || handoff_authority.authorize.budget_commit_index
                != hold.authorization_metadata.budget_commit_index
            || handoff_partition.canonical_json != hold_partition.canonical_json()
            || handoff_partition.evidence_digest != hold_partition.evidence_digest()
        {
            return Err(KernelError::Internal(
                "caller reservation handoff changed its reserved partition authority".to_string(),
            ));
        }
        chio_core_types::receipt::authoritative_spend::receipt_meets_guarantee_floor(
            handoff_receipt,
            "partition_escrowed",
        )
        .map_err(|_| {
            KernelError::Internal(
                "caller reservation handoff omitted valid signed partition admission lineage"
                    .to_string(),
            )
        })?;
    }

    let mut protocol_admission = handoff_metadata
        .get("protocol_admission")
        .cloned()
        .filter(serde_json::Value::is_object)
        .ok_or_else(|| {
            KernelError::Internal(
                "caller reservation handoff omitted its signed protocol admission lineage"
                    .to_string(),
            )
        })?;
    let completion_operation = completion_metadata
        .pointer("/protocol_admission/admission_operation")
        .cloned()
        .ok_or_else(|| {
            KernelError::Internal(
                "caller reservation completion omitted its terminal operation projection"
                    .to_string(),
            )
        })?;
    protocol_admission
        .as_object_mut()
        .ok_or_else(|| {
            KernelError::Internal(
                "caller reservation protocol admission lineage is not an object".to_string(),
            )
        })?
        .insert("admission_operation".to_string(), completion_operation);

    Ok(serde_json::json!({
        "protocol_admission": protocol_admission,
        "attribution": attribution,
    }))
}

impl ChioKernel {
    /// Settle every expired, unreconciled reserved budget hold at its reserved
    /// worst-case, forfeiting the reserved amount to realized spend. In the
    /// two-phase reserve/reconcile flow the only evidence a spend occurred is the
    /// caller's reconcile; an expired-and-unreconciled hold may correspond to a
    /// call that executed and spent, so releasing it would under-count real spend
    /// and fail open for a cumulative spend cap. Self-healing and fail-closed: a
    /// still-valid reserved hold and any reconciled/reversed/released hold are
    /// never touched, and a settled hold is idempotent under repeated reaps.
    /// Each call scans one bounded page in stable operation-id order; repeated
    /// calls advance a process-local cursor and wrap after the final page.
    pub fn reap_expired_reserved_budget_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, KernelError> {
        let mut reap_inventory_errors = CallerReservationReapFailures::default();
        let expiring_caller_reservations = if let Some(operation_store) =
            self.admission_operation_store.as_ref()
        {
            let after_operation_id = self
                .caller_reservation_reap_cursor
                .lock()
                .map_err(|_| {
                    KernelError::Internal(
                        "caller reservation reap cursor lock is poisoned".to_string(),
                    )
                })?
                .clone();
            let operations = operation_store.list_caller_reservation_reap_candidates(
                after_operation_id.as_deref(),
                MAX_CALLER_RESERVATION_REAP_OPERATIONS,
            )?;
            {
                let mut cursor = self.caller_reservation_reap_cursor.lock().map_err(|_| {
                    KernelError::Internal(
                        "caller reservation reap cursor lock is poisoned".to_string(),
                    )
                })?;
                *cursor = operations
                    .last()
                    .map(|operation| operation.operation_id().to_string());
            }
            let mut expiring = Vec::new();
            for mut operation in operations {
                let operation_id = operation.operation_id().to_string();
                let inspected = (|| -> Result<Option<AdmissionOperation>, KernelError> {
                    let expires_at = self.validated_caller_reservation_reap_expiry(
                        operation_store.as_ref(),
                        &operation,
                    )?;
                    if expires_at > now_unix_secs {
                        return Ok(None);
                    }
                    if operation.state() == AdmissionOperationState::CallerReservationCapturePending
                    {
                        self.recover_caller_reservation_capture_pending_handoff(
                            operation_store.as_ref(),
                            self.budget_store.as_ref(),
                            self.approval_store.as_deref(),
                            &operation,
                        )?;
                        let recovered = operation_store
                            .load(operation.operation_id())?
                            .ok_or_else(|| {
                                KernelError::Internal(format!(
                                    "caller reservation operation {} disappeared during expiry recovery",
                                    operation.operation_id()
                                ))
                            })?;
                        match recovered.state() {
                            AdmissionOperationState::CompensatedBeforeDispatch => {
                                if let Some(hold_id) = recovered.budget_hold_id() {
                                    self.release_reserved_sibling_share_for_hold(hold_id);
                                }
                                return Ok(None);
                            }
                            AdmissionOperationState::CallerReserved => operation = recovered,
                            AdmissionOperationState::OutcomeUnknownAfterDispatch => {}
                            state => {
                                return Err(KernelError::Internal(format!(
                                    "caller reservation expiry recovery stopped in {}",
                                    state.as_str()
                                )))
                            }
                        }
                    }
                    let hold_id = operation.budget_hold_id().ok_or_else(|| {
                        KernelError::Internal(format!(
                            "caller reservation operation {} has no budget hold",
                            operation.operation_id()
                        ))
                    })?;
                    let authorization = if operation.state()
                        == AdmissionOperationState::CallerReserved
                    {
                        self.resolve_caller_reserved_admission_for_nonce(
                            hold_id,
                            operation.capability_id(),
                            operation.request_id(),
                        )?
                        .authorization
                    } else {
                        self.load_recovery_budget_snapshot(operation_store.as_ref(), &operation)?
                            .authorization_request()?
                    };
                    let hold = self
                        .with_budget_store(|store| Ok(store.get_budget_hold(hold_id)?))?
                        .ok_or_else(|| {
                            KernelError::Internal(format!(
                                "caller reservation operation {} lost budget hold {hold_id}",
                                operation.operation_id()
                            ))
                        })?;
                    if authorization.hold_id.as_deref() != Some(hold.hold_id.as_str())
                        || authorization.capability_id != hold.capability_id
                        || authorization.grant_index != hold.grant_index
                        || authorization.requested_exposure_units != hold.authorized_exposure_units
                    {
                        return Err(KernelError::Internal(format!(
                            "caller reservation operation {} changed its expiring hold binding",
                            operation.operation_id()
                        )));
                    }
                    Ok(Some(operation))
                })();
                match inspected {
                    Ok(Some(operation)) => expiring.push(operation),
                    Ok(None) => {}
                    Err(error) => reap_inventory_errors.push(format!(
                        "operation {operation_id} validation failed: {error}"
                    )),
                }
            }
            expiring
        } else {
            Vec::new()
        };

        // Reserved holds this reap will settle (open, past their reserved expiry)
        // still hold their delegated child's sibling-sum share admitted. Capture
        // that set before settling so the parent's headroom is released once, and
        // only, for the holds the store actually forfeits. The predicate mirrors
        // the store reaper's contract (open + reserved_until <= now).
        let tracked = self.tracked_reserved_sibling_hold_ids();
        let expiring = self.with_budget_store(|store| {
            let mut expiring = Vec::new();
            for hold_id in &tracked {
                if let Some(hold) = store.get_budget_hold(hold_id)? {
                    if hold.disposition.is_open()
                        && hold
                            .reserved_until
                            .is_some_and(|until| until <= now_unix_secs)
                    {
                        expiring.push(hold_id.clone());
                    }
                }
            }
            Ok(expiring)
        })?;
        // Run the store reap but do NOT propagate its error yet. If the store
        // settled some holds before failing partway through the sweep, those
        // closed holds' sibling shares must still be released, or a closed hold's
        // admitted share leaks (the next sweep no longer sees it as open) and
        // wrongly denies valid sibling reservations until restart.
        let reap_result =
            self.with_budget_store(|store| Ok(store.reap_expired_reserved_holds(now_unix_secs)?));

        // Release the sibling share for exactly those expiring holds the store
        // actually closed. Re-query each hold's disposition: a hold now closed or
        // missing was forfeited, so its share is freed; a hold still open was not
        // settled by the store, so its share is retained. Fail-closed on the
        // re-query itself: a hold whose disposition cannot be read keeps its share
        // held, so a read error never frees a share for a still-open hold.
        for hold_id in &expiring {
            let closed = match self.with_budget_store(|store| Ok(store.get_budget_hold(hold_id)?)) {
                Ok(Some(hold)) => !hold.disposition.is_open(),
                Ok(None) => true,
                Err(_) => false,
            };
            if closed {
                self.release_reserved_sibling_share_for_hold(hold_id);
            }
        }

        let mut terminal_errors = reap_inventory_errors;
        if let Some(operation_store) = self.admission_operation_store.as_ref() {
            for expected in expiring_caller_reservations {
                let Some(hold_id) = expected.budget_hold_id() else {
                    terminal_errors.push(format!(
                        "operation {} lost its budget hold binding",
                        expected.operation_id()
                    ));
                    continue;
                };
                let hold = match self.with_budget_store(|store| Ok(store.get_budget_hold(hold_id)?))
                {
                    Ok(hold) => hold,
                    Err(error) => {
                        terminal_errors.push(format!(
                            "operation {} hold read failed: {error}",
                            expected.operation_id()
                        ));
                        continue;
                    }
                };
                let Some(hold) = hold else {
                    terminal_errors.push(format!(
                        "operation {} hold {hold_id} disappeared after reap",
                        expected.operation_id()
                    ));
                    continue;
                };
                if hold.disposition.is_open() {
                    terminal_errors.push(format!(
                        "operation {} hold {hold_id} remained open after its bounded expiry reap",
                        expected.operation_id()
                    ));
                    continue;
                }
                let current = match operation_store.load(expected.operation_id()) {
                    Ok(Some(operation)) => operation,
                    Ok(None) => {
                        terminal_errors.push(format!(
                            "operation {} disappeared after hold expiry",
                            expected.operation_id()
                        ));
                        continue;
                    }
                    Err(error) => {
                        terminal_errors.push(format!(
                            "operation {} reload failed after hold expiry: {error}",
                            expected.operation_id()
                        ));
                        continue;
                    }
                };
                let terminal_reason = if hold.disposition == BudgetHoldDispositionView::Expired {
                    "caller reservation expired before authoritative reconcile"
                } else {
                    "caller reservation hold closed without an authoritative operation completion"
                };
                let finalize =
                    if current.state() == AdmissionOperationState::OutcomeUnknownAfterDispatch {
                        self.validate_terminal_receipt_binding_with_store(
                            operation_store.as_ref(),
                            &current,
                        )
                        .map(|()| current)
                    } else {
                        self.finalize_caller_reservation_outcome_unknown(
                            &current,
                            terminal_reason,
                            Some(serde_json::json!({
                                "caller_reservation_recovery": {
                                    "hold_id": hold_id,
                                    "hold_disposition": hold.disposition.as_str(),
                                    "closed_exposure_units": hold.authorized_exposure_units,
                                }
                            })),
                        )
                    };
                self.release_reserved_sibling_share_for_hold(hold_id);
                if let Err(error) = finalize {
                    let recovered = operation_store
                        .load(expected.operation_id())
                        .ok()
                        .flatten()
                        .filter(|operation| {
                            operation.state()
                                == AdmissionOperationState::OutcomeUnknownAfterDispatch
                        })
                        .is_some_and(|operation| {
                            self.validate_terminal_receipt_binding_with_store(
                                operation_store.as_ref(),
                                &operation,
                            )
                            .is_ok()
                        });
                    if !recovered {
                        terminal_errors.push(format!(
                            "operation {} terminalization failed: {error}",
                            expected.operation_id()
                        ));
                    }
                }
            }
        }

        let settled = match reap_result {
            Ok(settled) => settled,
            Err(error) => {
                if terminal_errors.is_empty() {
                    return Err(error);
                }
                let error = bounded_reap_error(&error);
                return Err(KernelError::Internal(format!(
                    "reserved hold reap failed: {error}; caller reservation terminalization failures: {}",
                    terminal_errors.summary()
                )));
            }
        };
        if terminal_errors.is_empty() {
            Ok(settled)
        } else {
            Err(KernelError::Internal(format!(
                "caller reservation terminalization failures: {}",
                terminal_errors.summary()
            )))
        }
    }

    /// Reconcile the reserved budget hold named by a presented execution nonce
    /// at its measured realized cost, producing an authoritative mediated-spend
    /// receipt. Fail-closed at every step.
    ///
    /// Order of checks:
    /// 1. The presented `arguments` must hash to the nonce's bound parameter
    ///    hash (the caller must have executed the exact call the nonce authorizes).
    /// 2. The nonce must name a reserved hold (`reserved_hold_id`).
    /// 3. The realized currency must equal the currency the grant/hold was
    ///    authorized in. This is checked BEFORE the nonce is consumed, so a
    ///    mismatch is rejected fail-closed without burning the nonce or settling,
    ///    and an unchecked caller-supplied currency never reaches a signed receipt.
    /// 4. The nonce is VERIFIED (schema, expiry, signature under the kernel key,
    ///    and that it has not already been consumed) but is NOT yet marked
    ///    consumed. A forged or tampered nonce fails the signature check; an
    ///    already-settled nonce fails the replay check; neither is ever marked.
    /// 5. The named hold must still be open. A missing or already-closed hold is
    ///    rejected. This open-to-closed settle is the mutual-exclusion point: two
    ///    concurrent presentations of the same nonce cannot both settle because
    ///    the store closes the hold atomically (the second finds it closed and is
    ///    rejected here), so deferring the nonce mark opens no double-settle window.
    /// 6. The hold is settled at `min(realized_cost, reserved)` -- realized cost
    ///    is CLAMPED to the reserved worst-case, since the payer never authorized
    ///    more than the reserved envelope. A realized cost of zero settles the
    ///    hold at zero, releasing the entire reserved amount back to the grant.
    /// 7. The nonce is marked consumed (single-use replay) ONLY after the settle
    ///    succeeds. A transient store error at step 6 therefore leaves the nonce
    ///    unconsumed, so the caller can re-present the same signed nonce and settle
    ///    at realized cost instead of forfeiting the reservation. Once the hold is
    ///    closed a replay is already rejected at step 5, so marking after
    ///    settlement is safe.
    /// 8. A completed allow receipt is signed with the reconciled hold lineage
    ///    and the nonce id, so `is_authoritative_spend_receipt` accepts it.
    pub fn reconcile_reserved_authorization_by_nonce(
        &self,
        presented_nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        realized_cost: &ToolInvocationCost,
    ) -> Result<ToolCallResponse, KernelError> {
        // (1) The caller must present the exact arguments the nonce authorized.
        // The nonce binding carries the signed parameter hash; comparing it to
        // the presented arguments ties the realized-cost claim to the signed call.
        let action = ToolCallAction::from_parameters(arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash arguments for reconcile-by-nonce binding: {e}"
            ))
        })?;
        if action.parameter_hash != presented_nonce.nonce.bound_to.parameter_hash {
            return Err(KernelError::Internal(
                "reconcile-by-nonce arguments do not match the nonce parameter binding".to_string(),
            ));
        }

        // (2) The nonce must name a reserved hold. Read the signed hold id up
        // front so the caller-supplied realized currency can be validated against
        // the reserved grant currency BEFORE the nonce is verified and consumed.
        let reserved_hold_id = presented_nonce.reserved_hold_id().ok_or_else(|| {
            KernelError::Internal(
                "presented nonce does not name a reserved budget hold; nothing to reconcile"
                    .to_string(),
            )
        })?;
        let bound_capability_id = presented_nonce.nonce.bound_to.capability_id.clone();

        // (3) Currency check (fail-closed): reject a realized currency that
        // differs from the currency the grant/hold was authorized in, before
        // settling or signing, so an unchecked caller-supplied currency is never
        // stamped onto a signed authoritative receipt. Doing this ahead of nonce
        // consumption means a mismatch does not burn the nonce (the caller can
        // retry with the correct currency). Defers to the signature check below
        // when the named hold is absent, so a forged/tampered nonce is still
        // rejected as a nonce error rather than masked by hold-not-found.
        self.with_budget_store(|store| {
            let Some(hold) = store.get_budget_hold(reserved_hold_id)? else {
                return Ok(());
            };
            match hold.reserved_currency.as_deref() {
                Some(reserved) if reserved == realized_cost.currency => Ok(()),
                Some(reserved) => Err(KernelError::Internal(format!(
                    "reconcile-by-nonce realized currency `{}` does not match the reserved grant currency `{reserved}`",
                    realized_cost.currency
                ))),
                // A non-monetary invocation reservation carries zero exposure and
                // no currency, so there is no monetary envelope to validate; it
                // settles the invocation at zero. A monetary hold always records
                // its currency when reserved, so a missing currency alongside a
                // non-zero exposure is a corrupted reserved hold and stays
                // fail-closed.
                None if hold.authorized_exposure_units == 0 => Ok(()),
                None => Err(KernelError::Internal(format!(
                    "reconcile-by-nonce cannot validate realized currency for reserved hold `{reserved_hold_id}`: no reserved grant currency recorded"
                ))),
            }
        })?;

        // (4) Verify the nonce but do NOT consume it yet. Verifying against the
        // nonce's own binding makes the binding self-check trivially pass while
        // the signature check (over the full body including reserved_hold_id)
        // still rejects any forgery or tamper, and the replay peek rejects an
        // already-consumed nonce. The single-use mark is deferred to step 7 so a
        // transient settle error below leaves the nonce replayable for a retry.
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal(
                "execution nonce store is not installed; cannot reconcile by nonce".to_string(),
            )
        })?;
        let now_unix = current_unix_timestamp();
        let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
        verify_execution_nonce_without_consume(
            presented_nonce,
            &self.config.keypair.public_key(),
            &presented_nonce.nonce.bound_to,
            now,
            store,
        )
        .map_err(|error| {
            KernelError::Internal(format!("reconcile-by-nonce rejected the nonce: {error}"))
        })?;
        let caller_reservation_terms = match self.admission_operation_store.as_ref() {
            Some(operation_store) => {
                match operation_store.load_by_budget_hold_id(reserved_hold_id)? {
                    Some(_) => {
                        let reserving_request_id =
                            presented_nonce.reserving_request_id().ok_or_else(|| {
                                KernelError::Internal(
                                    "operation-owned reserved nonce omitted its reserving request id"
                                        .to_string(),
                                )
                            })?;
                        Some(self.resolve_caller_reserved_admission_for_nonce(
                            reserved_hold_id,
                            &bound_capability_id,
                            reserving_request_id,
                        )?)
                    }
                    None => None,
                }
            }
            None => None,
        };
        let caller_handoff_receipt = if let Some(terms) = caller_reservation_terms.as_ref() {
            let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "operation-owned reserved nonce lost its admission operation store".to_string(),
                )
            })?;
            Some(self.validated_caller_reserved_handoff_receipt_with_store(
                operation_store.as_ref(),
                &terms.operation,
            )?)
        } else {
            None
        };
        let caller_completion = if let Some(terms) = caller_reservation_terms.as_ref() {
            Some(self.project_caller_reservation_completion(terms.operation.operation_id())?)
        } else {
            None
        };

        // (5)+(6) Look up the exact hold and reconcile it, all under one budget
        // store lock so the open-state check and the settle are atomic.
        let realized_units = realized_cost.units;
        let (hold, committed_before, reconcile, trusted_handoff_metadata, receipt_grant_index) =
            self.with_budget_store(|store| {
                let hold: BudgetHoldSnapshot =
                    store.get_budget_hold(reserved_hold_id)?.ok_or_else(|| {
                        KernelError::Internal(format!(
                            "reserved budget hold `{reserved_hold_id}` not found for reconcile-by-nonce"
                        ))
                    })?;
                if !hold.disposition.is_open() {
                    return Err(KernelError::Internal(format!(
                        "reserved budget hold `{reserved_hold_id}` is {} and cannot be reconciled",
                        hold.disposition.as_str()
                    )));
                }
                if hold.capability_id != bound_capability_id {
                    return Err(KernelError::Internal(format!(
                        "reserved budget hold `{reserved_hold_id}` capability does not match the nonce binding"
                    )));
                }
                let authorize_event_id = hold
                    .authorization_metadata
                    .event_id
                    .as_deref()
                    .ok_or_else(|| {
                        KernelError::Internal(format!(
                            "reserved budget hold `{reserved_hold_id}` omitted its authorization event"
                        ))
                    })?;
                if hold.authorization_metadata.authority != hold.authority {
                    return Err(KernelError::Internal(format!(
                        "reserved budget hold `{reserved_hold_id}` changed its authorization authority"
                    )));
                }
                self.validate_hard_budget_commit_metadata_for_store(
                    store,
                    &hold.authorization_metadata,
                    authorize_event_id,
                    hold.authority.as_ref(),
                    None,
                    "reconcile-by-nonce authorization snapshot",
                )?;
                let admission_operation = if let Some(terms) = caller_reservation_terms.as_ref() {
                    if terms.authorization.hold_id.as_deref() != Some(hold.hold_id.as_str())
                        || hold.capability_id != terms.authorization.capability_id
                        || hold.grant_index != terms.authorization.grant_index
                        || hold.authorized_exposure_units
                            != terms.authorization.requested_exposure_units
                    {
                        return Err(KernelError::Internal(format!(
                            "reserved budget hold `{reserved_hold_id}` changed its operation-owned authorization binding"
                        )));
                    }
                    terms.authorization.admission_operation.clone()
                } else {
                    None
                };
                let operation_owned = admission_operation.is_some();
                let expected_admission_operation = admission_operation.clone();
                let receipt_grant_index = u32::try_from(hold.grant_index).map_err(|_| {
                    KernelError::Internal(
                        "reserved budget hold grant index exceeds the receipt attribution range"
                            .to_string(),
                    )
                })?;
                let trusted_handoff_metadata = match (
                    caller_handoff_receipt.as_ref(),
                    caller_completion.as_ref(),
                ) {
                    (Some(handoff_receipt), Some((completion_metadata, _))) => Some(
                        trusted_caller_reconciliation_metadata(
                            handoff_receipt,
                            completion_metadata,
                            &hold,
                            presented_nonce,
                            receipt_grant_index,
                        )?,
                    ),
                    (None, None)
                        if hold.authorization_metadata.guarantee_level
                            == crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed =>
                    {
                        return Err(KernelError::Internal(
                            "partition escrow reconcile requires a validated caller reservation handoff"
                                .to_string(),
                        ));
                    }
                    (None, None) => None,
                    _ => {
                        return Err(KernelError::Internal(
                            "caller reservation reconcile lost its trusted handoff projection"
                                .to_string(),
                        ));
                    }
                };

                let exposed = hold.remaining_exposure_units;
                // CLAMP: the payer authorized only the reserved worst-case.
                let realized = realized_units.min(exposed);
                let committed_before = match store.get_usage(&hold.capability_id, hold.grant_index)? {
                    Some(usage) => usage.committed_cost_units()?,
                    None => exposed,
                };
                let reconcile_event_id = format!("{}:reconcile", hold.hold_id);
                let reconcile = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                    capability_id: hold.capability_id.clone(),
                    grant_index: hold.grant_index,
                    exposed_cost_units: exposed,
                    realized_spend_units: realized,
                    hold_id: Some(hold.hold_id.clone()),
                    event_id: Some(reconcile_event_id.clone()),
                    authority: hold.authority.clone(),
                    admission_operation,
                })?;
                self.validate_budget_terminal_decision_for_store(
                    store,
                    &reconcile,
                    BudgetTerminalDecisionExpectation {
                        authorization_metadata: &hold.authorization_metadata,
                        expected_event_id: &reconcile_event_id,
                        expected_authority: hold.authority.as_ref(),
                        expected_capability_id: Some(&hold.capability_id),
                        expected_grant_index: hold.grant_index,
                        expected_hold_id: &hold.hold_id,
                        expected_admission_operation: expected_admission_operation.as_ref(),
                        expected_mutation_kind:
                            crate::budget_store::BudgetMutationKind::ReconcileSpend,
                        expected_exposure_units: exposed,
                        expected_realized_spend_units: realized,
                        expected_invocation_state: if operation_owned {
                            BudgetInvocationReservationState::Captured
                        } else {
                            BudgetInvocationReservationState::Absent
                        },
                        expected_monetary_state: BudgetMonetaryHoldState::Reconciled,
                        stage: "reconcile-by-nonce terminal commit",
                    },
                )?;
                Ok((
                    hold,
                    committed_before,
                    reconcile,
                    trusted_handoff_metadata,
                    receipt_grant_index,
                ))
            })?;

        // The reserved hold is now settled (closed), so release the sibling-sum
        // share it kept admitted, freeing the parent's headroom for a sibling.
        // Done before the receipt is built so a later signing error still frees
        // the headroom; a no-op for a root hold that never held a share.
        self.release_reserved_sibling_share_for_hold(reserved_hold_id);

        let exposed = hold.remaining_exposure_units;
        let realized = realized_units.min(exposed);

        // Currency stamped onto the signed receipt. A monetary hold validated the
        // realized currency against the reserved grant currency in step 3, so it is
        // safe to echo. A zero-exposure invocation reserve carries no reserved
        // currency and never validated the realized currency, so normalize it to the
        // inert value rather than land an unchecked caller-supplied string on a
        // signed artifact (the step-3 guarantee).
        let receipt_currency = if hold.reserved_currency.is_some() {
            realized_cost.currency.clone()
        } else {
            INVOCATION_RECONCILE_RECEIPT_CURRENCY.to_string()
        };

        // Preserve the exact authorize lineage retained with the hold, including
        // its commit index and signed partition allocation proof.
        let authorize_metadata = hold.authorization_metadata.clone();
        let charge = BudgetChargeResult {
            grant_index: hold.grant_index,
            cost_charged: exposed,
            currency: receipt_currency.clone(),
            budget_total: exposed,
            new_committed_cost_units: committed_before,
            budget_hold_id: hold.hold_id.clone(),
            authorize_metadata,
            admission_operation: caller_reservation_terms
                .as_ref()
                .and_then(|terms| terms.authorization.admission_operation.clone()),
        };
        let budget_metadata = self.budget_execution_receipt_metadata(
            &charge,
            Some(("reconciled", &reconcile)),
            Some(presented_nonce.nonce_id()),
        )?;

        // Report the GRANT's budget and delegation lineage, recorded on the reserved
        // hold at reserve time, so dashboards and reports see the grant ceiling and
        // true lineage rather than this single reservation's exposure. A grant with a
        // per-invocation cap but no `max_total_cost` records u64::MAX as its sentinel
        // ceiling; that sentinel must never surface on a signed receipt, so treat it
        // (and a hold reserved before these fields existed, or a zero-exposure
        // invocation reserve) as having no recorded ceiling and fall back to this
        // reservation's bounded exposure and the nonce subject.
        let grant_budget_total = hold
            .reserved_budget_total
            .filter(|&total| total != u64::MAX)
            .unwrap_or(exposed);
        // Remaining is the grant ceiling minus the grant's TOTAL committed spend
        // after this settle (committed_before - exposed + realized), not just this
        // reconcile's realized cost. Subtracting only the realized cost would ignore
        // every other reservation or spend already committed on the grant and
        // overstate the remaining budget. Mirrors the inline unmeasured-cost path.
        let committed_after = reconcile.committed_cost_units_after;
        let financial = FinancialReceiptMetadata {
            grant_index: receipt_grant_index,
            cost_charged: realized,
            currency: receipt_currency,
            budget_remaining: grant_budget_total.saturating_sub(committed_after),
            budget_total: grant_budget_total,
            delegation_depth: hold.reserved_delegation_depth.unwrap_or(0),
            root_budget_holder: hold
                .reserved_root_budget_holder
                .clone()
                .unwrap_or_else(|| presented_nonce.nonce.bound_to.subject_id.clone()),
            // Stamp the rail transaction id captured for a prepaid MustPrepay
            // reservation (recorded on the reserved hold at reserve time), so the
            // authoritative reconciled receipt ties the spend to the payment that
            // funded it. `None` for a mediated reserve that carried no prepayment.
            payment_reference: hold.reserved_payment_reference.clone(),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: realized_cost.breakdown.clone(),
            oracle_evidence: None,
            attempted_cost: None,
        };
        let mut metadata = merge_metadata_objects(
            Some(serde_json::json!({ "financial": financial })),
            Some(budget_metadata),
        );
        metadata = merge_metadata_objects(metadata, trusted_handoff_metadata);

        let receipt = (|| {
            let receipt_content = receipt_content_for_output(None, None)?;
            let frozen_policy_hash = caller_reservation_terms
                .as_ref()
                .map_or(self.config.policy_hash.as_str(), |terms| {
                    terms.operation.policy_hash()
                });
            self.build_and_sign_receipt_for_policy_hash(
                ReceiptParams {
                    request_id: presented_nonce.reserving_request_id(),
                    capability_id: &bound_capability_id,
                    tool_name: &presented_nonce.nonce.bound_to.tool_name,
                    server_id: &presented_nonce.nonce.bound_to.tool_server,
                    decision: Decision::Allow,
                    action,
                    content_hash: receipt_content.content_hash,
                    canonical_content: receipt_content.canonical_content,
                    metadata,
                    timestamp: now_unix,
                    trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
                    tenant_id: None,
                },
                frozen_policy_hash,
            )
        })();
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(terms) = caller_reservation_terms.as_ref() {
                    self.terminalize_failed_caller_reservation_reconcile(
                        terms.operation.operation_id(),
                        reserved_hold_id,
                        &error,
                    )?;
                }
                return Err(error);
            }
        };

        let request_id = presented_nonce
            .reserving_request_id()
            .map(str::to_string)
            .unwrap_or_else(|| receipt.id.clone());

        // The nonce is already consumed and the hold closed: settlement is
        // IRREVERSIBLE by this point. If the durable receipt persist fails now, a
        // retry cannot recreate the receipt (the nonce is a replay, the hold is
        // closed), so the caller would be left with no authoritative receipt for a
        // spend that really settled. Return the signed authoritative receipt and log
        // the persist failure rather than surfacing only the error. A settlement
        // FAILURE earlier (forged/replayed nonce, closed hold, currency mismatch)
        // still fails closed above, before this point.
        if let Some((_, intent)) = caller_completion.as_ref() {
            let Some(terms) = caller_reservation_terms.as_ref() else {
                return Err(KernelError::Internal(
                    "caller completion intent omitted its operation terms".to_string(),
                ));
            };
            if let Err(error) = self.commit_caller_reservation_completion_receipt(intent, &receipt)
            {
                self.terminalize_failed_caller_reservation_reconcile(
                    terms.operation.operation_id(),
                    reserved_hold_id,
                    &error,
                )?;
                return Err(error);
            }
        } else if let Err(error) = self.record_chio_receipt(&receipt) {
            warn!(
                request_id = %request_id,
                hold_id = %hold.hold_id,
                nonce_id = %presented_nonce.nonce_id(),
                receipt_id = %receipt.id,
                reason = %redacted!(&error),
                "durable receipt persistence failed after an irreversible reconcile settlement; \
                 returning the signed authoritative receipt"
            );
        }

        // (7) The hold and, for an operation-owned reservation, its terminal
        // signed outbox are durable before the single-use nonce mark. A consume
        // failure is non-fatal because the closed hold rejects every replay.
        if let Err(error) = consume_execution_nonce(
            store,
            presented_nonce.nonce_id(),
            presented_nonce.expires_at(),
        ) {
            warn!(
                nonce_id = %presented_nonce.nonce_id(),
                hold_id = %hold.hold_id,
                reason = %redacted!(&error),
                "failed to mark the reconcile nonce consumed after an irreversible settlement; \
                 the closed hold still rejects any replay"
            );
        }

        info!(
            request_id = %request_id,
            hold_id = %hold.hold_id,
            nonce_id = %presented_nonce.nonce_id(),
            realized,
            reserved = exposed,
            "reconciled reserved authorization by nonce"
        );

        Ok(ToolCallResponse {
            request_id,
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }

    fn terminalize_failed_caller_reservation_reconcile(
        &self,
        operation_id: &str,
        hold_id: &str,
        primary: &KernelError,
    ) -> Result<(), KernelError> {
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation reconcile lost its admission operation store".to_string(),
            )
        })?;
        let operation = operation_store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!(
                "caller reservation operation {operation_id} disappeared after settlement"
            ))
        })?;
        let terminal = match operation.state() {
            AdmissionOperationState::CallerReserved => self
                .finalize_caller_reservation_outcome_unknown(
                    &operation,
                    "authoritative caller reservation receipt could not be signed after settlement",
                    Some(serde_json::json!({
                        "caller_reservation_recovery": {
                            "hold_id": hold_id,
                            "hold_disposition": "reconciled",
                            "receipt_signing_failed": true,
                        }
                    })),
                )
                .map(|_| ()),
            AdmissionOperationState::Completed
            | AdmissionOperationState::OutcomeUnknownAfterDispatch => self
                .validate_terminal_receipt_binding_with_store(
                    operation_store.as_ref(),
                    &operation,
                ),
            state => Err(KernelError::Internal(format!(
                "caller reservation operation {operation_id} reached unexpected state {} after settlement",
                state.as_str()
            ))),
        };
        terminal.map_err(|error| {
            KernelError::Internal(format!(
                "{primary}; caller reservation settlement terminalization failed: {error}"
            ))
        })
    }
}
