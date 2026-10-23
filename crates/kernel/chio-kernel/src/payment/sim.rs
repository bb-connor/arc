//! Deterministic, no-broadcast payment adapter for sim-first acceptance lanes.
//!
//! Custody-neutral by construction: it performs no HTTP, holds no key, and moves
//! no funds. Authorization ids are a pure function of the request so smokes are
//! reproducible. It echoes the governed binding into `metadata` so the settled
//! tool-call receipt carries the governed intent hash and approval token id.

use crate::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentRailMode, PaymentResult, RailSettlementState, RailSettlementStatus,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Deterministic no-broadcast payment adapter.
///
/// Authorizations are remembered per reference for the life of the process so
/// recovery can answer the settlement-state query. A restarted adapter has no
/// authorizations and reports `NoAuthorization`, which is accurate because it
/// moved no funds.
#[derive(Debug, Clone, Default)]
pub struct SimPaymentAdapter {
    authorizations: Arc<Mutex<HashMap<String, String>>>,
}

impl SimPaymentAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn deterministic_id(
        prefix: &str,
        reference: &str,
        amount_units: u64,
        currency: &str,
    ) -> String {
        let seed = format!("{reference}|{amount_units}|{currency}");
        let digest = chio_core::sha256_hex(seed.as_bytes());
        format!("{prefix}-{}", &digest[..32])
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
        let authorization_id = Self::deterministic_id(
            "sim",
            &request.reference,
            request.amount_units,
            &request.currency,
        );
        self.authorizations
            .lock()
            .map_err(|_| PaymentError::RailError("sim authorization ledger is poisoned".into()))?
            .insert(request.reference.clone(), authorization_id.clone());
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
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "sim", "action": "capture" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
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
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
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
        let recorded = self
            .authorizations
            .lock()
            .map_err(|_| PaymentError::RailError("sim authorization ledger is poisoned".into()))?
            .get(reference)
            .cloned();
        let Some(recorded) = recorded else {
            return match authorization_id {
                None => Ok(RailSettlementState::NoAuthorization),
                Some(_) => Err(PaymentError::RailError(
                    "sim has no authorization for the queried reference".into(),
                )),
            };
        };
        if authorization_id.is_some_and(|expected| expected != recorded) {
            return Err(PaymentError::RailError(
                "sim authorization does not match the queried identifier".into(),
            ));
        }
        Ok(RailSettlementState::Settled {
            result: PaymentResult {
                transaction_id: recorded.clone(),
                settlement_status: RailSettlementStatus::Settled,
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
        let captured = adapter.capture("sim-abc", 100, "USD", "req-1").unwrap();
        assert_eq!(captured.settlement_status, RailSettlementStatus::Settled);
        let released = adapter.release("sim-abc", "req-1").unwrap();
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
            "payment rail error: sim has no authorization for the queried reference"
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
}
