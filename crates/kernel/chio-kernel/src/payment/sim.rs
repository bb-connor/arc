//! Deterministic, no-broadcast payment adapter for sim-first acceptance lanes.
//!
//! Custody-neutral by construction: it performs no HTTP, holds no key, and moves
//! no funds. Authorization ids are a pure function of the request so smokes are
//! reproducible. It echoes the governed binding into `metadata` so the settled
//! tool-call receipt carries the governed intent hash and approval token id.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::payment::{
    bind_operation_authorization, bind_operation_payment_result,
    validate_operation_authorize_request, validate_payment_operation_binding,
    OperationPaymentCaptureRequest, OperationPaymentRefundRequest, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentResult,
    RailSettlementState, RailSettlementStatus,
};

/// Deterministic no-broadcast payment adapter.
#[derive(Debug, Clone, Default)]
pub struct SimPaymentAdapter {
    operation_authorizations: Arc<Mutex<HashMap<String, (String, PaymentAuthorization)>>>,
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
    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        true
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
        Ok(PaymentAuthorization {
            authorization_id,
            settled: false,
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

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        validate_operation_authorize_request(operation_id, request_binding_hash, request)?;
        let candidate = bind_operation_authorization(
            self.authorize(request)?,
            operation_id,
            request_binding_hash,
        )?;
        let mut authorizations = self.operation_authorizations.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation authorization state poisoned".to_string())
        })?;
        match authorizations.get(operation_id) {
            Some((existing_binding, authorization))
                if existing_binding == request_binding_hash =>
            {
                Ok(authorization.clone())
            }
            Some(_) => Err(PaymentError::RailError(
                "sim payment operation id was reused with a different request binding"
                    .to_string(),
            )),
            None => {
                authorizations.insert(
                    operation_id.to_string(),
                    (request_binding_hash.to_string(), candidate.clone()),
                );
                Ok(candidate)
            }
        }
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let authorizations = self.operation_authorizations.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation authorization state poisoned".to_string())
        })?;
        match authorizations.get(operation_id) {
            Some((existing_binding, authorization))
                if existing_binding == request_binding_hash =>
            {
                Ok(Some(authorization.clone()))
            }
            Some(_) => Err(PaymentError::RailError(
                "sim payment operation id was reused with a different request binding"
                    .to_string(),
            )),
            None => Ok(None),
        }
    }

    fn capture_for_operation(
        &self,
        request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(request.operation_id, request.request_binding_hash)?;
        bind_operation_payment_result(
            self.capture(
                request.authorization_id,
                request.amount_units,
                request.currency,
                request.reference,
            )?,
            request.operation_id,
            request.request_binding_hash,
        )
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        bind_operation_payment_result(
            self.release(authorization_id, reference)?,
            operation_id,
            request_binding_hash,
        )
    }

    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(request.operation_id, request.request_binding_hash)?;
        bind_operation_payment_result(
            self.refund(
                request.transaction_id,
                request.amount_units,
                request.currency,
                request.reference,
            )?,
            request.operation_id,
            request.request_binding_hash,
        )
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        _reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        match self.lookup_authorization_for_operation(operation_id, request_binding_hash)? {
            Some(authorization)
                if authorization_id.is_none_or(|expected| {
                    expected == authorization.authorization_id.as_str()
                }) =>
            {
                Ok(RailSettlementState::Held {
                    authorization_id: authorization.authorization_id,
                })
            }
            Some(_) => Err(PaymentError::RailError(
                "sim operation settlement lookup named a different authorization".to_string(),
            )),
            None => Ok(RailSettlementState::NoAuthorization),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reference: &str, amount: u64) -> PaymentAuthorizeRequest {
        PaymentAuthorizeRequest {
            operation_id: None,
            request_binding_hash: None,
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
    fn authorize_is_deterministic_and_unsettled() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let b = adapter.authorize(&request("req-1", 100)).unwrap();
        assert_eq!(a.authorization_id, b.authorization_id);
        assert!(a.authorization_id.starts_with("sim-"));
        assert!(!a.settled, "sim must leave capture/release to the kernel");
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
    fn operation_authorization_lookup_is_exact_and_idempotent() {
        let adapter = SimPaymentAdapter::new();
        let operation_id = "sim-operation-1";
        let request_binding_hash = "ab".repeat(32);
        let mut operation_request = request("req-operation-1", 100);
        operation_request.operation_id = Some(operation_id.to_string());
        operation_request.request_binding_hash = Some(request_binding_hash.clone());

        assert!(adapter.supports_operation_authorization_recovery());
        assert!(adapter.supports_operation_payment_mutations());
        assert!(adapter
            .lookup_authorization_for_operation(operation_id, &request_binding_hash)
            .unwrap()
            .is_none());
        let first = adapter
            .authorize_for_operation(operation_id, &request_binding_hash, &operation_request)
            .unwrap();
        let retry = adapter
            .authorize_for_operation(operation_id, &request_binding_hash, &operation_request)
            .unwrap();
        let looked_up = adapter
            .lookup_authorization_for_operation(operation_id, &request_binding_hash)
            .unwrap()
            .expect("operation authorization");
        assert_eq!(first, retry);
        assert_eq!(first, looked_up);
        assert_eq!(first.metadata["operationId"], operation_id);
        assert_eq!(
            first.metadata["requestBindingHash"],
            request_binding_hash
        );
        assert!(adapter
            .lookup_authorization_for_operation(operation_id, &"cd".repeat(32))
            .is_err());
    }
}
