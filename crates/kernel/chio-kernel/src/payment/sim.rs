//! Deterministic, no-broadcast payment adapter for sim-first acceptance lanes.
//!
//! Custody-neutral by construction: it performs no HTTP, holds no key, and moves
//! no funds. Authorization ids are a pure function of the payment reference so
//! smokes are reproducible and a restarted adapter can verify journaled ids. It
//! echoes the governed binding into `metadata` so the settled tool-call receipt
//! carries the governed intent hash and approval token id.

use crate::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentRailMode, PaymentResult, RailSettlementState, RailSettlementStatus,
};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const LEDGER_CAPACITY: usize = 65_536;

/// Deterministic no-broadcast payment adapter.
///
/// The latest settlement status is remembered per reference so recovery can
/// answer the settlement-state query. The ledger keeps the most recent
/// `LEDGER_CAPACITY` references. A reference that was evicted, or that a
/// restarted adapter never saw, reports `NoAuthorization`, which is accurate
/// because the adapter moved no funds. Terminal calls verify the identifier
/// against the reference, so journaled calls complete after a restart.
#[derive(Debug, Clone)]
pub struct SimPaymentAdapter {
    ledger: Arc<Mutex<Ledger>>,
}

#[derive(Debug)]
struct Ledger {
    capacity: usize,
    statuses: HashMap<String, RailSettlementStatus>,
    order: VecDeque<String>,
}

impl Ledger {
    fn record(&mut self, reference: &str, status: RailSettlementStatus, overwrite: bool) {
        if let Some(entry) = self.statuses.get_mut(reference) {
            if overwrite {
                *entry = status;
            }
            return;
        }
        while self.order.len() >= self.capacity {
            match self.order.pop_front() {
                Some(evicted) => {
                    self.statuses.remove(&evicted);
                }
                None => break,
            }
        }
        self.statuses.insert(reference.to_owned(), status);
        self.order.push_back(reference.to_owned());
    }
}

impl Default for SimPaymentAdapter {
    fn default() -> Self {
        Self::with_capacity(LEDGER_CAPACITY)
    }
}

impl SimPaymentAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            ledger: Arc::new(Mutex::new(Ledger {
                capacity,
                statuses: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    fn ledger(&self) -> Result<std::sync::MutexGuard<'_, Ledger>, PaymentError> {
        self.ledger
            .lock()
            .map_err(|_| PaymentError::RailError("sim authorization ledger is poisoned".into()))
    }

    fn record_status(
        &self,
        reference: &str,
        authorization_id: &str,
        status: RailSettlementStatus,
    ) -> Result<(), PaymentError> {
        if authorization_id != Self::authorization_id(reference) {
            return Err(PaymentError::RailError(
                "sim authorization does not match the recorded identifier".into(),
            ));
        }
        self.ledger()?.record(reference, status, true);
        Ok(())
    }

    fn authorization_id(reference: &str) -> String {
        let digest = chio_core::sha256_hex(reference.as_bytes());
        format!("sim-{}", &digest[..32])
    }
}

impl PaymentAdapter for SimPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "sim"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let authorization_id = Self::authorization_id(&request.reference);
        self.ledger()?
            .record(&request.reference, RailSettlementStatus::Settled, false);
        Ok(PaymentAuthorization {
            authorization_id,
            state: PaymentAuthorizationState::PrepaidFinal,
            metadata: serde_json::json!({
                "adapter": "sim",
                "mode": "prepaid_no_broadcast",
                "governed": request.governed,
                "commerce": request.commerce,
            }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.record_status(reference, authorization_id, RailSettlementStatus::Settled)?;
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "sim", "action": "capture" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.record_status(reference, authorization_id, RailSettlementStatus::Released)?;
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "sim", "action": "release" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.record_status(reference, transaction_id, RailSettlementStatus::Refunded)?;
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "sim", "action": "refund" }),
        })
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let recorded = Self::authorization_id(reference);
        if authorization_id.is_some_and(|expected| expected != recorded) {
            return Err(PaymentError::RailError(
                "sim authorization does not match the queried identifier".into(),
            ));
        }
        let status = self.ledger()?.statuses.get(reference).copied();
        let Some(status) = status else {
            return match authorization_id {
                None => Ok(RailSettlementState::NoAuthorization),
                Some(_) => Err(PaymentError::RailError(
                    "sim has no authorization for the queried reference".into(),
                )),
            };
        };
        Ok(RailSettlementState::Settled {
            result: PaymentResult {
                transaction_id: recorded.clone(),
                settlement_status: status,
                metadata: serde_json::json!({ "adapter": "sim", "action": "settlement_state" }),
            },
            authorization_id: recorded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reference: &str, amount: u64) -> PaymentAuthorizeRequest {
        PaymentAuthorizeRequest {
            amount_units: amount,
            currency: "USD".to_string(),
            payer: "agent-1".to_string(),
            payee: "srv-1".to_string(),
            reference: reference.to_string(),
            governed: None,
            commerce: None,
        }
    }

    #[test]
    fn authorize_is_deterministic_and_prepaid() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let b = adapter.authorize(&request("req-1", 100)).unwrap();
        assert_eq!(a.authorization_id, b.authorization_id);
        assert!(a.authorization_id.starts_with("sim-"));
        assert!(a.state.is_final(), "sim authorization is prepaid and final");
    }

    #[test]
    fn distinct_requests_get_distinct_ids() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let c = adapter.authorize(&request("req-2", 100)).unwrap();
        assert_ne!(a.authorization_id, c.authorization_id);
    }

    #[test]
    fn capture_and_release_map_to_settled_and_released() {
        let adapter = SimPaymentAdapter::new();
        let id = adapter
            .authorize(&request("req-1", 100))
            .unwrap()
            .authorization_id;
        let captured = adapter.capture(&id, 100, "USD", "req-1").unwrap();
        assert_eq!(captured.settlement_status, RailSettlementStatus::Settled);
        let released = adapter.release(&id, "req-1").unwrap();
        assert_eq!(released.settlement_status, RailSettlementStatus::Released);
    }

    #[test]
    fn settlement_state_reports_no_authorization_before_authorize() {
        let adapter = SimPaymentAdapter::new();
        assert_eq!(
            adapter.settlement_state("req-1", None).unwrap(),
            RailSettlementState::NoAuthorization
        );
        let error = adapter
            .settlement_state("req-1", Some("sim-x"))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "payment rail error: sim authorization does not match the queried identifier"
        );
    }

    #[test]
    fn settlement_state_rejects_a_valid_identifier_without_a_record() {
        let id = SimPaymentAdapter::new()
            .authorize(&request("req-1", 100))
            .unwrap()
            .authorization_id;
        let restarted = SimPaymentAdapter::new();
        let error = restarted.settlement_state("req-1", Some(&id)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "payment rail error: sim has no authorization for the queried reference"
        );
        assert_eq!(
            restarted.settlement_state("req-1", None).unwrap(),
            RailSettlementState::NoAuthorization
        );
    }

    #[test]
    fn settlement_state_reports_the_prepaid_final_authorization() {
        let adapter = SimPaymentAdapter::new();
        let authorization = adapter.authorize(&request("req-1", 100)).unwrap();
        let expected = RailSettlementState::Settled {
            authorization_id: authorization.authorization_id.clone(),
            result: PaymentResult {
                transaction_id: authorization.authorization_id.clone(),
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({ "adapter": "sim", "action": "settlement_state" }),
            },
        };
        assert_eq!(adapter.settlement_state("req-1", None).unwrap(), expected);
        assert_eq!(
            adapter
                .settlement_state("req-1", Some(&authorization.authorization_id))
                .unwrap(),
            expected
        );
        let error = adapter
            .settlement_state("req-1", Some("sim-other"))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "payment rail error: sim authorization does not match the queried identifier"
        );
        assert_eq!(
            adapter.settlement_state("req-2", None).unwrap(),
            RailSettlementState::NoAuthorization
        );
    }

    #[test]
    fn settlement_state_follows_release_and_refund() {
        let adapter = SimPaymentAdapter::new();
        let authorization = adapter.authorize(&request("req-1", 100)).unwrap();
        let id = authorization.authorization_id;
        let status = |adapter: &SimPaymentAdapter| match adapter
            .settlement_state("req-1", Some(&id))
            .unwrap()
        {
            RailSettlementState::Settled { result, .. } => result.settlement_status,
            other => panic!("expected settled state, got {other:?}"),
        };
        assert_eq!(status(&adapter), RailSettlementStatus::Settled);
        adapter.release(&id, "req-1").unwrap();
        assert_eq!(status(&adapter), RailSettlementStatus::Released);
        adapter.refund(&id, 100, "USD", "req-1").unwrap();
        assert_eq!(status(&adapter), RailSettlementStatus::Refunded);
    }

    #[test]
    fn authorize_retry_keeps_terminal_status() {
        let adapter = SimPaymentAdapter::new();
        let id = adapter
            .authorize(&request("req-1", 100))
            .unwrap()
            .authorization_id;
        adapter.release(&id, "req-1").unwrap();
        adapter.authorize(&request("req-1", 100)).unwrap();
        match adapter.settlement_state("req-1", None).unwrap() {
            RailSettlementState::Settled { result, .. } => {
                assert_eq!(result.settlement_status, RailSettlementStatus::Released);
            }
            other => panic!("expected settled state, got {other:?}"),
        }
    }

    #[test]
    fn terminal_calls_reject_unknown_or_mismatched_bindings() {
        let adapter = SimPaymentAdapter::new();
        let unknown = adapter.capture("sim-x", 1, "USD", "req-1").unwrap_err();
        assert_eq!(
            unknown.to_string(),
            "payment rail error: sim authorization does not match the recorded identifier"
        );
        assert_eq!(
            adapter.settlement_state("req-1", None).unwrap(),
            RailSettlementState::NoAuthorization
        );
        let id = adapter
            .authorize(&request("req-1", 100))
            .unwrap()
            .authorization_id;
        for error in [
            adapter.capture("sim-other", 1, "USD", "req-1").unwrap_err(),
            adapter.release("sim-other", "req-1").unwrap_err(),
            adapter.refund("sim-other", 1, "USD", "req-1").unwrap_err(),
        ] {
            assert_eq!(
                error.to_string(),
                "payment rail error: sim authorization does not match the recorded identifier"
            );
        }
        match adapter.settlement_state("req-1", Some(&id)).unwrap() {
            RailSettlementState::Settled { result, .. } => {
                assert_eq!(result.settlement_status, RailSettlementStatus::Settled);
            }
            other => panic!("expected settled state, got {other:?}"),
        }
    }

    fn status(adapter: &SimPaymentAdapter, reference: &str) -> RailSettlementStatus {
        match adapter.settlement_state(reference, None).unwrap() {
            RailSettlementState::Settled { result, .. } => result.settlement_status,
            other => panic!("expected settled state, got {other:?}"),
        }
    }

    #[test]
    fn restarted_adapter_completes_journaled_terminal_calls() {
        let id = SimPaymentAdapter::new()
            .authorize(&request("req-1", 100))
            .unwrap()
            .authorization_id;
        let restarted = SimPaymentAdapter::new();
        let refunded = restarted.refund(&id, 100, "USD", "req-1").unwrap();
        assert_eq!(refunded.settlement_status, RailSettlementStatus::Refunded);
        assert_eq!(refunded.transaction_id, id);
        assert_eq!(status(&restarted, "req-1"), RailSettlementStatus::Refunded);

        let id = SimPaymentAdapter::new()
            .authorize(&request("req-2", 100))
            .unwrap()
            .authorization_id;
        let restarted = SimPaymentAdapter::new();
        let captured = restarted.capture(&id, 40, "USD", "req-2").unwrap();
        assert_eq!(captured.settlement_status, RailSettlementStatus::Settled);
        let released = restarted.release(&id, "req-2").unwrap();
        assert_eq!(released.settlement_status, RailSettlementStatus::Released);

        let error = SimPaymentAdapter::new()
            .refund(&id, 100, "USD", "req-1")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "payment rail error: sim authorization does not match the recorded identifier"
        );
    }

    #[test]
    fn ledger_retains_at_most_its_capacity() {
        let adapter = SimPaymentAdapter::with_capacity(2);
        let first = adapter
            .authorize(&request("req-1", 100))
            .unwrap()
            .authorization_id;
        adapter.authorize(&request("req-2", 100)).unwrap();
        adapter.authorize(&request("req-3", 100)).unwrap();
        assert_eq!(
            adapter.settlement_state("req-1", None).unwrap(),
            RailSettlementState::NoAuthorization
        );
        assert_eq!(status(&adapter, "req-2"), RailSettlementStatus::Settled);
        assert_eq!(status(&adapter, "req-3"), RailSettlementStatus::Settled);
        let refunded = adapter.refund(&first, 100, "USD", "req-1").unwrap();
        assert_eq!(refunded.settlement_status, RailSettlementStatus::Refunded);
        assert_eq!(status(&adapter, "req-1"), RailSettlementStatus::Refunded);
        assert_eq!(
            adapter.settlement_state("req-2", None).unwrap(),
            RailSettlementState::NoAuthorization
        );
    }
}
