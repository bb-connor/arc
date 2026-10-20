use chio_settle::{SettlementAttemptClaim, SettlementHookError, SettlementIdempotencyKey};

use super::settlement_observer::SettlementObserverStatus;
use super::{ChioKernel, KernelError};

impl ChioKernel {
    /// Claim up to `limit` due settlement attempts and run each through the
    /// installed settlement hook.
    ///
    /// Each claimed row is rebuilt from its stored receipt and completed
    /// through the claimed-outcome CAS, so a `Retryable` attempt is re-run
    /// once its retry deadline passes and dead-letters when the retry policy
    /// is exhausted. Returns the number of rows claimed; a kernel without a
    /// settlement runtime claims nothing.
    pub fn drain_settlement_attempts(&self, limit: usize) -> Result<usize, KernelError> {
        let Some(runtime) = self.settlement_observer.as_ref() else {
            return Ok(0);
        };
        let claim_now_ms = self.read_authority_time()?.get();
        let claims = runtime.claim_due(claim_now_ms, limit).map_err(|error| {
            KernelError::Internal(format!("settlement drain claim failed: {error}"))
        })?;
        for claim in &claims {
            let status = self.drained_settlement_status(claim);
            runtime.record_claimed_status(
                claim,
                &status,
                self.read_authority_time()?.get().max(claim_now_ms),
            );
        }
        Ok(claims.len())
    }

    fn drained_settlement_status(
        &self,
        claim: &SettlementAttemptClaim,
    ) -> SettlementObserverStatus {
        let Some(store) = self.receipt_store.as_ref() else {
            return SettlementObserverStatus::hook_failed(
                &SettlementHookError::InvalidObservation(
                    "settlement drain has no receipt store".to_string(),
                ),
            );
        };
        let receipt = match store.load_chio_receipt(&claim.receipt_id) {
            Ok(Some(receipt))
                if receipt.id == claim.receipt_id && receipt.timestamp == claim.finalized_at =>
            {
                receipt
            }
            Ok(Some(_)) => {
                return SettlementObserverStatus::hook_failed(
                    &SettlementHookError::InvalidObservation(
                        "stored receipt does not match the claimed settlement row".to_string(),
                    ),
                );
            }
            Ok(None) => {
                return SettlementObserverStatus::hook_failed(
                    &SettlementHookError::InvalidObservation(
                        "claimed settlement receipt is not stored".to_string(),
                    ),
                );
            }
            Err(error) => {
                return SettlementObserverStatus::hook_failed(&SettlementHookError::Transient(
                    error.to_string(),
                ));
            }
        };
        self.run_settlement_observer(
            &receipt,
            &SettlementIdempotencyKey {
                receipt_id: claim.receipt_id.clone(),
                row_version: claim.row_version,
            },
        )
    }
}
