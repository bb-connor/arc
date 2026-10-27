//! Production settlement hook that records local settlement truth.

use std::sync::Arc;

use chio_core::receipt::economics::SettlementStatus;
use chio_settle::{
    ObservedSettlement, SettlementFailureCode, SettlementFailureReason, SettlementHook,
    SettlementHookError, SettlementIdempotencyKey, SettlementObservation, SettlementOutcome,
};

use crate::operator_report::SettlementReconciliationState;
use crate::receipt_store::{ReceiptStore, ReceiptStoreError};

const NON_FINAL_CHARGE_DETAIL: &str = "allowed charge recorded a non-final settlement status";
const RETAINED_PAYMENT_DETAIL: &str = "retained payment awaits payment journal resolution";

/// Settlement hook installed by [`crate::ChioKernel::install_settlement_ledger`].
///
/// The hook never calls a payment rail and never mutates receipt rows or
/// receipt bytes. Per observation:
///
/// - A charge whose receipt records `settled` gets one `reconciled`
///   `settlement_reconciliations` row carrying the payment reference, written
///   through the receipt store's serving writer. The row records the signed
///   receipt's historical settlement observation; it does not establish rail
///   finality. An existing row is kept, so a lease replay never overrides an
///   operator decision.
/// - A charge whose receipt records any other status is permanent. Durable
///   admission withholds pending terminal receipts, so a signed non-final
///   charge is a contract breach for the operator.
/// - A retained payment stays retryable, and dead-letters once the configured
///   retry policy is exhausted, until a bound settlement closure can be emitted.
pub struct KernelSettlementLedgerHook {
    receipt_store: Arc<dyn ReceiptStore>,
}

impl KernelSettlementLedgerHook {
    #[must_use]
    pub fn new(receipt_store: Arc<dyn ReceiptStore>) -> Self {
        Self { receipt_store }
    }

    fn record_settled(
        &self,
        receipt_id: &str,
        payment_reference: Option<&str>,
    ) -> Result<SettlementOutcome, SettlementHookError> {
        match self.receipt_store.record_settlement_reconciliation(
            receipt_id,
            SettlementReconciliationState::Reconciled,
            payment_reference,
        ) {
            Ok(_) => Ok(SettlementOutcome::accepted(transcript_id(
                receipt_id,
                payment_reference,
            ))),
            Err(ReceiptStoreError::NotFound(detail) | ReceiptStoreError::Unsupported(detail)) => {
                Err(SettlementHookError::InvalidObservation(detail))
            }
            Err(error) => Err(SettlementHookError::Transient(error.to_string())),
        }
    }
}

impl SettlementHook for KernelSettlementLedgerHook {
    fn observe(
        &self,
        observation: &SettlementObservation,
        idempotency_key: &SettlementIdempotencyKey,
    ) -> Result<SettlementOutcome, SettlementHookError> {
        if idempotency_key.receipt_id != observation.receipt_id {
            return Err(SettlementHookError::InvalidObservation(
                "settlement idempotency key does not match the observed receipt".to_string(),
            ));
        }
        match &observation.settlement {
            ObservedSettlement::Charge {
                status: SettlementStatus::Settled,
                payment_reference,
                ..
            } => self.record_settled(&observation.receipt_id, payment_reference.as_deref()),
            ObservedSettlement::Charge { .. } => Ok(SettlementOutcome::permanent(
                SettlementFailureReason::from_detail(
                    SettlementFailureCode::UnsupportedEconomicForm,
                    NON_FINAL_CHARGE_DETAIL,
                ),
            )),
            ObservedSettlement::RetainedPayment { .. } => Ok(SettlementOutcome::retryable(
                SettlementFailureReason::from_detail(
                    SettlementFailureCode::AwaitingRailResolution,
                    RETAINED_PAYMENT_DETAIL,
                ),
            )),
        }
    }
}

fn transcript_id(receipt_id: &str, payment_reference: Option<&str>) -> String {
    let mut material = Vec::new();
    for part in [receipt_id, payment_reference.unwrap_or_default()] {
        material.extend_from_slice(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        material.extend_from_slice(part.as_bytes());
    }
    chio_core::crypto::sha256_hex(&material)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::receipt::body::ChioReceipt;
    use chio_core::receipt::lineage::ChildRequestReceipt;

    use super::*;

    #[derive(Default)]
    struct ReconciliationStore {
        rows: Mutex<Vec<(String, SettlementReconciliationState, Option<String>)>>,
        missing: bool,
    }

    impl ReceiptStore for ReconciliationStore {
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn supports_settlement_reconciliation(&self) -> bool {
            true
        }

        fn record_settlement_reconciliation(
            &self,
            receipt_id: &str,
            state: SettlementReconciliationState,
            note: Option<&str>,
        ) -> Result<bool, ReceiptStoreError> {
            if self.missing {
                return Err(ReceiptStoreError::NotFound(format!(
                    "receipt {receipt_id} does not exist"
                )));
            }
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| ReceiptStoreError::Conflict("rows lock poisoned".to_string()))?;
            if rows.iter().any(|(id, _, _)| id == receipt_id) {
                return Ok(false);
            }
            rows.push((receipt_id.to_string(), state, note.map(str::to_string)));
            Ok(true)
        }
    }

    fn observation(settlement: ObservedSettlement) -> SettlementObservation {
        SettlementObservation::new("rcpt-1", 10, "srv", "tool", "cap", settlement, "ch", "ph")
    }

    fn charge(status: SettlementStatus) -> ObservedSettlement {
        ObservedSettlement::Charge {
            amount: MonetaryAmount {
                currency: "USD".to_string(),
                units: 100,
            },
            status,
            payment_reference: Some("pay-1".to_string()),
            hold_id: Some("hold-1".to_string()),
        }
    }

    fn key() -> SettlementIdempotencyKey {
        SettlementIdempotencyKey {
            receipt_id: "rcpt-1".to_string(),
            row_version: 1,
        }
    }

    fn observe(
        store: &Arc<ReconciliationStore>,
        settlement: ObservedSettlement,
    ) -> Result<SettlementOutcome, SettlementHookError> {
        let receipt_store: Arc<dyn ReceiptStore> = store.clone();
        KernelSettlementLedgerHook::new(receipt_store).observe(&observation(settlement), &key())
    }

    #[test]
    fn settled_charge_records_one_reconciled_row_and_replays_idempotently() {
        let store = Arc::new(ReconciliationStore::default());
        let first = observe(&store, charge(SettlementStatus::Settled));
        let replay = observe(&store, charge(SettlementStatus::Settled));

        let expected = SettlementOutcome::accepted(transcript_id("rcpt-1", Some("pay-1")));
        assert_eq!(first.ok(), Some(expected.clone()));
        assert_eq!(replay.ok(), Some(expected));
        let rows = store
            .rows
            .lock()
            .map(|rows| rows.clone())
            .unwrap_or_default();
        assert_eq!(
            rows,
            vec![(
                "rcpt-1".to_string(),
                SettlementReconciliationState::Reconciled,
                Some("pay-1".to_string()),
            )]
        );
    }

    #[test]
    fn non_final_charge_is_a_permanent_unsupported_economic_form() {
        for status in [
            SettlementStatus::Pending,
            SettlementStatus::Failed,
            SettlementStatus::NotApplicable,
        ] {
            let store = Arc::new(ReconciliationStore::default());
            assert_eq!(
                observe(&store, charge(status)).ok(),
                Some(SettlementOutcome::permanent(
                    SettlementFailureReason::from_detail(
                        SettlementFailureCode::UnsupportedEconomicForm,
                        NON_FINAL_CHARGE_DETAIL,
                    )
                ))
            );
            assert!(store
                .rows
                .lock()
                .map(|rows| rows.is_empty())
                .unwrap_or(false));
        }
    }

    #[test]
    fn retained_payment_waits_for_rail_resolution() {
        let store = Arc::new(ReconciliationStore::default());
        let outcome = observe(
            &store,
            ObservedSettlement::RetainedPayment {
                operation_id: "op-1".to_string(),
                hold_id: "hold-1".to_string(),
                exposure_units: 100,
            },
        );
        assert_eq!(
            outcome.ok(),
            Some(SettlementOutcome::retryable(
                SettlementFailureReason::from_detail(
                    SettlementFailureCode::AwaitingRailResolution,
                    RETAINED_PAYMENT_DETAIL,
                )
            ))
        );
        assert!(store
            .rows
            .lock()
            .map(|rows| rows.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn missing_receipt_is_an_invalid_observation() {
        let store = Arc::new(ReconciliationStore {
            missing: true,
            ..ReconciliationStore::default()
        });
        assert!(matches!(
            observe(&store, charge(SettlementStatus::Settled)),
            Err(SettlementHookError::InvalidObservation(detail))
                if detail == "receipt rcpt-1 does not exist"
        ));
    }

    #[test]
    fn mismatched_idempotency_key_is_rejected() {
        let receipt_store: Arc<dyn ReceiptStore> = Arc::new(ReconciliationStore::default());
        let result = KernelSettlementLedgerHook::new(receipt_store).observe(
            &observation(charge(SettlementStatus::Settled)),
            &SettlementIdempotencyKey {
                receipt_id: "rcpt-2".to_string(),
                row_version: 1,
            },
        );
        assert!(matches!(
            result,
            Err(SettlementHookError::InvalidObservation(detail))
                if detail == "settlement idempotency key does not match the observed receipt"
        ));
    }
}
