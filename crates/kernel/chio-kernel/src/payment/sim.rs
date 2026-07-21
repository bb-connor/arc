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
    operation_payments: Arc<Mutex<HashMap<String, SimOperationPayment>>>,
}

#[derive(Debug, Clone)]
struct SimOperationPayment {
    request_binding_hash: String,
    authorize_request: PaymentAuthorizeRequest,
    authorization: PaymentAuthorization,
    capture: Option<(SimCaptureInput, PaymentResult)>,
    release: Option<(SimReleaseInput, PaymentResult)>,
    refund: Option<(SimRefundInput, PaymentResult)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SimCaptureInput {
    authorization_id: String,
    amount_units: u64,
    currency: String,
    reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SimReleaseInput {
    authorization_id: String,
    reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SimRefundInput {
    transaction_id: String,
    amount_units: u64,
    currency: String,
    reference: String,
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
        let mut payments = self.operation_payments.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation payment state poisoned".to_string())
        })?;
        match payments.get(operation_id) {
            Some(payment)
                if payment.request_binding_hash == request_binding_hash
                    && payment.authorize_request == *request =>
            {
                Ok(payment.authorization.clone())
            }
            Some(_) => Err(PaymentError::RailError(
                "sim payment operation id was reused with different authorization input"
                    .to_string(),
            )),
            None => {
                payments.insert(
                    operation_id.to_string(),
                    SimOperationPayment {
                        request_binding_hash: request_binding_hash.to_string(),
                        authorize_request: request.clone(),
                        authorization: candidate.clone(),
                        capture: None,
                        release: None,
                        refund: None,
                    },
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
        let payments = self.operation_payments.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation payment state poisoned".to_string())
        })?;
        match payments.get(operation_id) {
            Some(payment) if payment.request_binding_hash == request_binding_hash => {
                Ok(Some(payment.authorization.clone()))
            }
            Some(_) => Err(PaymentError::RailError(
                "sim payment operation id was reused with a different request binding".to_string(),
            )),
            None => Ok(None),
        }
    }

    fn capture_for_operation(
        &self,
        request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(request.operation_id, request.request_binding_hash)?;
        let input = SimCaptureInput {
            authorization_id: request.authorization_id.to_string(),
            amount_units: request.amount_units,
            currency: request.currency.to_string(),
            reference: request.reference.to_string(),
        };
        let mut payments = self.operation_payments.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation payment state poisoned".to_string())
        })?;
        let payment = payments.get_mut(request.operation_id).ok_or_else(|| {
            PaymentError::RailError(
                "sim capture named an operation with no authorization".to_string(),
            )
        })?;
        if payment.request_binding_hash != request.request_binding_hash
            || payment.authorization.authorization_id != request.authorization_id
            || payment.authorize_request.reference != request.reference
            || payment.authorize_request.currency != request.currency
            || request.amount_units > payment.authorize_request.amount_units
        {
            return Err(PaymentError::RailError(
                "sim capture input does not match its operation authorization".to_string(),
            ));
        }
        if let Some((existing, result)) = payment.capture.as_ref() {
            return if existing == &input {
                Ok(result.clone())
            } else {
                Err(PaymentError::RailError(
                    "sim capture operation was retried with different input".to_string(),
                ))
            };
        }
        if payment.release.is_some() {
            return Err(PaymentError::RailError(
                "sim cannot capture a released operation authorization".to_string(),
            ));
        }
        let result = bind_operation_payment_result(
            self.capture(
                request.authorization_id,
                request.amount_units,
                request.currency,
                request.reference,
            )?,
            request.operation_id,
            request.request_binding_hash,
        )?;
        payment.capture = Some((input, result.clone()));
        Ok(result)
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let input = SimReleaseInput {
            authorization_id: authorization_id.to_string(),
            reference: reference.to_string(),
        };
        let mut payments = self.operation_payments.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation payment state poisoned".to_string())
        })?;
        let payment = payments.get_mut(operation_id).ok_or_else(|| {
            PaymentError::RailError(
                "sim release named an operation with no authorization".to_string(),
            )
        })?;
        if payment.request_binding_hash != request_binding_hash
            || payment.authorization.authorization_id != authorization_id
            || payment.authorize_request.reference != reference
        {
            return Err(PaymentError::RailError(
                "sim release input does not match its operation authorization".to_string(),
            ));
        }
        if let Some((existing, result)) = payment.release.as_ref() {
            return if existing == &input {
                Ok(result.clone())
            } else {
                Err(PaymentError::RailError(
                    "sim release operation was retried with different input".to_string(),
                ))
            };
        }
        if payment.capture.is_some() {
            return Err(PaymentError::RailError(
                "sim cannot release a captured operation authorization".to_string(),
            ));
        }
        let result = bind_operation_payment_result(
            self.release(authorization_id, reference)?,
            operation_id,
            request_binding_hash,
        )?;
        payment.release = Some((input, result.clone()));
        Ok(result)
    }

    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(request.operation_id, request.request_binding_hash)?;
        let input = SimRefundInput {
            transaction_id: request.transaction_id.to_string(),
            amount_units: request.amount_units,
            currency: request.currency.to_string(),
            reference: request.reference.to_string(),
        };
        let mut payments = self.operation_payments.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation payment state poisoned".to_string())
        })?;
        let payment = payments.get_mut(request.operation_id).ok_or_else(|| {
            PaymentError::RailError("sim refund named an unknown operation".to_string())
        })?;
        if payment.request_binding_hash != request.request_binding_hash {
            return Err(PaymentError::RailError(
                "sim refund input does not match its operation authorization".to_string(),
            ));
        }
        if let Some((existing, result)) = payment.refund.as_ref() {
            return if existing == &input {
                Ok(result.clone())
            } else {
                Err(PaymentError::RailError(
                    "sim refund operation was retried with different input".to_string(),
                ))
            };
        }
        if payment.release.is_some() {
            return Err(PaymentError::RailError(
                "sim cannot refund a released operation authorization".to_string(),
            ));
        }
        let Some((capture_input, capture_result)) = payment.capture.as_ref() else {
            return Err(PaymentError::RailError(
                "sim cannot refund an operation before capture".to_string(),
            ));
        };
        if capture_result.transaction_id != request.transaction_id
            || capture_input.reference != request.reference
            || capture_input.currency != request.currency
            || request.amount_units > capture_input.amount_units
        {
            return Err(PaymentError::RailError(
                "sim refund input does not match its operation capture".to_string(),
            ));
        }
        let result = bind_operation_payment_result(
            self.refund(
                request.transaction_id,
                request.amount_units,
                request.currency,
                request.reference,
            )?,
            request.operation_id,
            request.request_binding_hash,
        )?;
        payment.refund = Some((input, result.clone()));
        Ok(result)
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let payments = self.operation_payments.lock().map_err(|_| {
            PaymentError::Unavailable("sim operation payment state poisoned".to_string())
        })?;
        let Some(payment) = payments.get(operation_id) else {
            return Ok(RailSettlementState::NoAuthorization);
        };
        if payment.request_binding_hash != request_binding_hash {
            return Err(PaymentError::RailError(
                "sim payment operation id was reused with a different request binding".to_string(),
            ));
        }
        if payment.authorize_request.reference != reference {
            return Err(PaymentError::RailError(
                "sim operation settlement lookup named a different reference".to_string(),
            ));
        }
        if authorization_id
            .is_some_and(|expected| expected != payment.authorization.authorization_id.as_str())
        {
            return Err(PaymentError::RailError(
                "sim operation settlement lookup named a different authorization".to_string(),
            ));
        }
        if let Some((_, result)) = payment.refund.as_ref() {
            return Ok(RailSettlementState::Settled {
                authorization_id: payment.authorization.authorization_id.clone(),
                result: result.clone(),
            });
        }
        if let Some((_, result)) = payment.capture.as_ref() {
            return Ok(RailSettlementState::Settled {
                authorization_id: payment.authorization.authorization_id.clone(),
                result: result.clone(),
            });
        }
        if payment.release.is_some() {
            return Ok(RailSettlementState::NoAuthorization);
        }
        Ok(RailSettlementState::Held {
            authorization_id: payment.authorization.authorization_id.clone(),
        })
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
        assert_eq!(first.metadata["requestBindingHash"], request_binding_hash);
        assert!(adapter
            .lookup_authorization_for_operation(operation_id, &"cd".repeat(32))
            .is_err());

        let mut changed_request = operation_request.clone();
        changed_request.amount_units += 1;
        assert!(adapter
            .authorize_for_operation(operation_id, &request_binding_hash, &changed_request)
            .is_err());
    }

    #[test]
    fn operation_settlement_tracks_capture_and_refund_with_exact_retries() {
        let adapter = SimPaymentAdapter::new();
        let operation_id = "sim-operation-capture-refund";
        let request_binding_hash = "12".repeat(32);
        let reference = "req-operation-capture-refund";
        let mut operation_request = request(reference, 100);
        operation_request.operation_id = Some(operation_id.to_string());
        operation_request.request_binding_hash = Some(request_binding_hash.clone());
        let authorization = adapter
            .authorize_for_operation(operation_id, &request_binding_hash, &operation_request)
            .unwrap();

        assert_eq!(
            adapter
                .settlement_state_for_operation(
                    operation_id,
                    &request_binding_hash,
                    reference,
                    Some(&authorization.authorization_id),
                )
                .unwrap(),
            RailSettlementState::Held {
                authorization_id: authorization.authorization_id.clone(),
            }
        );

        let capture_request = OperationPaymentCaptureRequest {
            operation_id,
            request_binding_hash: &request_binding_hash,
            authorization_id: &authorization.authorization_id,
            amount_units: 75,
            currency: "USD",
            reference,
        };
        let captured = adapter.capture_for_operation(capture_request).unwrap();
        assert_eq!(
            adapter.capture_for_operation(capture_request).unwrap(),
            captured,
            "an exact capture retry must return the original operation result"
        );
        assert_eq!(
            adapter
                .settlement_state_for_operation(
                    operation_id,
                    &request_binding_hash,
                    reference,
                    Some(&authorization.authorization_id),
                )
                .unwrap(),
            RailSettlementState::Settled {
                authorization_id: authorization.authorization_id.clone(),
                result: captured.clone(),
            },
            "recovery must observe a captured operation as settled, never held"
        );
        assert!(adapter
            .release_for_operation(
                operation_id,
                &request_binding_hash,
                &authorization.authorization_id,
                reference,
            )
            .is_err());

        let refund_request = OperationPaymentRefundRequest {
            operation_id,
            request_binding_hash: &request_binding_hash,
            transaction_id: &captured.transaction_id,
            amount_units: 75,
            currency: "USD",
            reference,
        };
        let refunded = adapter.refund_for_operation(refund_request).unwrap();
        assert_eq!(
            adapter.refund_for_operation(refund_request).unwrap(),
            refunded,
            "an exact refund retry must return the original operation result"
        );
        assert_eq!(refunded.settlement_status, RailSettlementStatus::Refunded);
        assert_eq!(
            adapter
                .settlement_state_for_operation(
                    operation_id,
                    &request_binding_hash,
                    reference,
                    Some(&authorization.authorization_id),
                )
                .unwrap(),
            RailSettlementState::Settled {
                authorization_id: authorization.authorization_id,
                result: refunded,
            }
        );

        assert!(adapter
            .refund_for_operation(OperationPaymentRefundRequest {
                amount_units: 74,
                ..refund_request
            })
            .is_err());
    }

    #[test]
    fn operation_release_is_terminal_and_observed_as_no_authorization() {
        let adapter = SimPaymentAdapter::new();
        let operation_id = "sim-operation-release";
        let request_binding_hash = "34".repeat(32);
        let reference = "req-operation-release";
        let mut operation_request = request(reference, 100);
        operation_request.operation_id = Some(operation_id.to_string());
        operation_request.request_binding_hash = Some(request_binding_hash.clone());
        let authorization = adapter
            .authorize_for_operation(operation_id, &request_binding_hash, &operation_request)
            .unwrap();

        let released = adapter
            .release_for_operation(
                operation_id,
                &request_binding_hash,
                &authorization.authorization_id,
                reference,
            )
            .unwrap();
        assert_eq!(
            adapter
                .release_for_operation(
                    operation_id,
                    &request_binding_hash,
                    &authorization.authorization_id,
                    reference,
                )
                .unwrap(),
            released
        );
        assert_eq!(
            adapter
                .settlement_state_for_operation(
                    operation_id,
                    &request_binding_hash,
                    reference,
                    Some(&authorization.authorization_id),
                )
                .unwrap(),
            RailSettlementState::NoAuthorization
        );
        assert!(adapter
            .capture_for_operation(OperationPaymentCaptureRequest {
                operation_id,
                request_binding_hash: &request_binding_hash,
                authorization_id: &authorization.authorization_id,
                amount_units: 100,
                currency: "USD",
                reference,
            })
            .is_err());
    }
}
