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

use super::*;

use crate::budget_store::{BudgetHoldSnapshot, BudgetReconcileHoldRequest};
use crate::execution_nonce::{verify_execution_nonce, SignedExecutionNonce};

impl ChioKernel {
    /// Settle every expired, unreconciled reserved budget hold at its reserved
    /// worst-case, forfeiting the reserved amount to realized spend. In the
    /// two-phase reserve/reconcile flow the only evidence a spend occurred is the
    /// caller's reconcile; an expired-and-unreconciled hold may correspond to a
    /// call that executed and spent, so releasing it would under-count real spend
    /// and fail open for a cumulative spend cap. Self-healing and fail-closed: a
    /// still-valid reserved hold and any reconciled/reversed/released hold are
    /// never touched, and a settled hold is idempotent under repeated reaps.
    /// Returns the number of holds settled. The sidecar drives this on a timer
    /// (startup wiring is a later task); this method is the reachable primitive.
    pub fn reap_expired_reserved_budget_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, KernelError> {
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
        let settled =
            self.with_budget_store(|store| Ok(store.reap_expired_reserved_holds(now_unix_secs)?))?;
        for hold_id in expiring {
            self.release_reserved_sibling_share_for_hold(&hold_id);
        }
        Ok(settled)
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
    /// 4. The nonce is verified (schema, expiry, signature under the kernel key,
    ///    single-use replay) and CONSUMED. A second reconcile of the same nonce
    ///    is rejected as a replay; a forged or tampered nonce fails the signature
    ///    check and is never consumed.
    /// 5. The named hold must still be open. A missing or already-closed hold is
    ///    rejected.
    /// 6. The hold is settled at `min(realized_cost, reserved)` -- realized cost
    ///    is CLAMPED to the reserved worst-case, since the payer never authorized
    ///    more than the reserved envelope. A realized cost of zero settles the
    ///    hold at zero, releasing the entire reserved amount back to the grant.
    /// 7. A completed allow receipt is signed with the reconciled hold lineage
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
                None => Err(KernelError::Internal(format!(
                    "reconcile-by-nonce cannot validate realized currency for reserved hold `{reserved_hold_id}`: no reserved grant currency recorded"
                ))),
            }
        })?;

        // (4) Verify and CONSUME the nonce. Verifying against the nonce's own
        // binding makes the binding self-check trivially pass while the signature
        // check (over the full body including reserved_hold_id) still rejects any
        // forgery or tamper, and the store reservation enforces single-use.
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal(
                "execution nonce store is not installed; cannot reconcile by nonce".to_string(),
            )
        })?;
        let now_unix = current_unix_timestamp();
        let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
        verify_execution_nonce(
            presented_nonce,
            &self.config.keypair.public_key(),
            &presented_nonce.nonce.bound_to,
            now,
            store,
        )
        .map_err(|error| {
            KernelError::Internal(format!("reconcile-by-nonce rejected the nonce: {error}"))
        })?;

        // (5)+(6) Look up the exact hold and reconcile it, all under one budget
        // store lock so the open-state check and the settle are atomic.
        let realized_units = realized_cost.units;
        let (hold, committed_before, reconcile, guarantee_level, budget_profile, metering_profile) =
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

                let exposed = hold.remaining_exposure_units;
                // CLAMP: the payer authorized only the reserved worst-case.
                let realized = realized_units.min(exposed);
                let committed_before = match store.get_usage(&hold.capability_id, hold.grant_index)? {
                    Some(usage) => usage.committed_cost_units()?,
                    None => exposed,
                };
                let reconcile = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                    capability_id: hold.capability_id.clone(),
                    grant_index: hold.grant_index,
                    exposed_cost_units: exposed,
                    realized_spend_units: realized,
                    hold_id: Some(hold.hold_id.clone()),
                    event_id: Some(format!("{}:reconcile", hold.hold_id)),
                    authority: hold.authority.clone(),
                })?;
                Ok((
                    hold,
                    committed_before,
                    reconcile,
                    store.budget_guarantee_level(),
                    store.budget_authority_profile(),
                    store.budget_metering_profile(),
                ))
            })?;

        // The reserved hold is now settled (closed), so release the sibling-sum
        // share it kept admitted, freeing the parent's headroom for a sibling.
        // Done before the receipt is built so a later signing error still frees
        // the headroom; a no-op for a root hold that never held a share.
        self.release_reserved_sibling_share_for_hold(reserved_hold_id);

        let exposed = hold.remaining_exposure_units;
        let realized = realized_units.min(exposed);

        // Reconstruct the authorize lineage from the reserved hold so the
        // receipt records the same guarantee/authority context the reserving
        // authorization committed, plus the reconcile terminal and the nonce id.
        let authorize_metadata = BudgetCommitMetadata {
            authority: hold.authority.clone(),
            guarantee_level,
            budget_profile,
            metering_profile,
            budget_commit_index: None,
            event_id: Some(format!("{}:authorize", hold.hold_id)),
        };
        let charge = BudgetChargeResult {
            grant_index: hold.grant_index,
            cost_charged: exposed,
            currency: realized_cost.currency.clone(),
            budget_total: exposed,
            new_committed_cost_units: committed_before,
            budget_hold_id: hold.hold_id.clone(),
            authorize_metadata,
        };
        let budget_metadata = self.budget_execution_receipt_metadata(
            &charge,
            Some(("reconciled", &reconcile)),
            Some(presented_nonce.nonce_id()),
        );

        let financial = FinancialReceiptMetadata {
            grant_index: hold.grant_index as u32,
            cost_charged: realized,
            currency: realized_cost.currency.clone(),
            // Framed on the reconciled hold's reserved envelope: reconcile-by-nonce
            // settles a single hold from the nonce alone, without the originating
            // grant's full ceiling. `budget_remaining` is the amount released back.
            budget_remaining: exposed.saturating_sub(realized),
            budget_total: exposed,
            delegation_depth: 0,
            root_budget_holder: presented_nonce.nonce.bound_to.subject_id.clone(),
            payment_reference: None,
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: realized_cost.breakdown.clone(),
            oracle_evidence: None,
            attempted_cost: None,
        };
        let metadata = merge_metadata_objects(
            Some(serde_json::json!({ "financial": financial })),
            Some(budget_metadata),
        );

        let receipt_content = receipt_content_for_output(None, None)?;
        let receipt = self.build_and_sign_receipt(ReceiptParams {
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
        })?;
        self.record_chio_receipt(&receipt)?;

        let request_id = presented_nonce
            .reserving_request_id()
            .map(str::to_string)
            .unwrap_or_else(|| receipt.id.clone());

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
}
