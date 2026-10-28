use chio_core::receipt::body::ChioReceipt;
use chio_settle::{SettlementAttemptClaim, SettlementHookError, SettlementIdempotencyKey};

use crate::settlement_routing::SettlementCompletion;
use crate::ReceiptStoreError;

use super::settlement_observer::SettlementObserverStatus;
use super::{ChioKernel, KernelError};

/// Claimed settlement attempts one drain pass resolved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettlementDrainReport {
    /// Claims whose outcome was committed.
    pub completed: usize,
    /// Claims another worker reclaimed after this pass's lease lapsed.
    pub lost_leases: usize,
}

impl ChioKernel {
    /// Claim up to `limit` due settlement attempts and run each through the
    /// installed settlement hook.
    ///
    /// Each claimed row is rebuilt from its stored receipt and completed
    /// through the claimed-outcome CAS, so a `Retryable` attempt is re-run
    /// once its retry deadline passes and dead-letters when the retry policy
    /// is exhausted. A claim or completion persistence failure returns
    /// `SettlementDrain` and leaves the remaining claimed rows leased until
    /// their lease lapses. A kernel without a settlement runtime claims nothing.
    pub fn drain_settlement_attempts(
        &self,
        limit: usize,
    ) -> Result<SettlementDrainReport, KernelError> {
        let Some(runtime) = self.settlement_observer.as_ref() else {
            return Ok(SettlementDrainReport::default());
        };
        let claim_now_ms = self.read_authority_time()?.get();
        let claims = runtime
            .claim_due(claim_now_ms, limit)
            .map_err(KernelError::SettlementDrain)?;
        let mut report = SettlementDrainReport::default();
        for chunk in claims.chunks(256) {
            let ids: Vec<_> = chunk
                .iter()
                .map(|claim| claim.receipt_id.as_str())
                .collect();
            let receipts = self
                .receipt_store
                .as_ref()
                .map(|store| store.load_chio_receipts(&ids));
            for (index, claim) in chunk.iter().enumerate() {
                let status = match &receipts {
                    Some(Ok(receipts)) if receipts.len() != chunk.len() => {
                        SettlementObserverStatus::hook_failed(
                            &SettlementHookError::InvalidObservation(
                                "settlement receipt batch length does not match the claimed rows"
                                    .to_string(),
                            ),
                        )
                    }
                    Some(Ok(receipts)) => {
                        self.loaded_settlement_status(claim, Ok(receipts[index].as_ref()))
                    }
                    Some(Err(_)) | None => self.drained_settlement_status(claim),
                };
                let completion = runtime
                    .complete_claim(
                        claim,
                        &status,
                        self.read_authority_time()?.get().max(claim_now_ms),
                    )
                    .map_err(KernelError::SettlementDrain)?;
                match completion {
                    SettlementCompletion::Recorded(_) => report.completed += 1,
                    SettlementCompletion::LostLease => report.lost_leases += 1,
                }
            }
        }
        Ok(report)
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
        let loaded = store.load_chio_receipt(&claim.receipt_id);
        self.loaded_settlement_status(claim, loaded.as_ref().map(Option::as_ref))
    }

    fn loaded_settlement_status(
        &self,
        claim: &SettlementAttemptClaim,
        loaded: Result<Option<&ChioReceipt>, &ReceiptStoreError>,
    ) -> SettlementObserverStatus {
        let receipt = match loaded {
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
        super::settlement_observer::run_observer(
            self.settlement_observer
                .as_ref()
                .map(crate::settlement_routing::SettlementObserverRuntime::hook_ref),
            receipt,
            self.settlement_observer.as_ref().map_or(
                &[],
                crate::settlement_routing::SettlementObserverRuntime::drain_keys,
            ),
            &SettlementIdempotencyKey {
                receipt_id: claim.receipt_id.clone(),
                row_version: claim.row_version,
            },
        )
    }
}
