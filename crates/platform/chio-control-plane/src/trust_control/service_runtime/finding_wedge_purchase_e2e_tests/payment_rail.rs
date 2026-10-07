//! Reference-bound test rails for durable purchase compensation.
use super::*;
use chio_kernel::RailSettlementState;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct PaymentCalls {
    pub(super) authorizations: AtomicU64,
    pub(super) captures: AtomicU64,
    pub(super) releases: AtomicU64,
    records: Mutex<BTreeMap<String, PaymentRecord>>,
}

struct PaymentRecord {
    request: PaymentAuthorizeRequest,
    state: PaymentObservation,
    terminal_operations: Vec<(TerminalOperation, PaymentResult)>,
}

enum PaymentObservation {
    Authorizing,
    Held(PaymentAuthorization),
    Settled {
        authorization: PaymentAuthorization,
        result: PaymentResult,
    },
}

impl PaymentObservation {
    fn authorization(&self) -> Option<&PaymentAuthorization> {
        match self {
            Self::Authorizing => None,
            Self::Held(authorization) | Self::Settled { authorization, .. } => Some(authorization),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum TerminalOperation {
    Capture { amount_units: u64, currency: String },
    Release,
    Refund { amount_units: u64, currency: String },
}

impl PaymentCalls {
    fn records(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, PaymentRecord>>, PaymentError> {
        self.records
            .lock()
            .map_err(|_| PaymentError::Unavailable("fixture rail state lock poisoned".into()))
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
        state: PaymentAuthorizationState,
        prefix: &str,
        hook: Option<&(dyn Fn() -> Result<(), String> + Send + Sync)>,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let authorization_id = format!("{prefix}:{}", request.reference);
        {
            let mut records = self.records()?;
            if let Some(record) = records.get(&request.reference) {
                if record.request != *request {
                    return Err(PaymentError::RailError(
                        "fixture authorization reference changed".into(),
                    ));
                }
                let existing = record.state.authorization().ok_or_else(|| {
                    PaymentError::Unavailable("fixture authorization is in progress".into())
                })?;
                if existing.state != state || existing.authorization_id != authorization_id {
                    return Err(PaymentError::RailError(
                        "fixture authorization rail mode changed".into(),
                    ));
                }
                return Ok(existing.clone());
            }
            records.insert(
                request.reference.clone(),
                PaymentRecord {
                    request: request.clone(),
                    state: PaymentObservation::Authorizing,
                    terminal_operations: Vec::new(),
                },
            );
        }
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        // The observer must see uncertainty throughout this hook. The hook can
        // itself query the rail, so no ledger lock crosses this boundary.
        if let Some(hook) = hook {
            hook().map_err(PaymentError::RailError)?;
        }
        let authorization = PaymentAuthorization {
            authorization_id,
            state,
            metadata: serde_json::json!({}),
        };
        let mut records = self.records()?;
        let record = records.get_mut(&request.reference).ok_or_else(|| {
            PaymentError::Unavailable("fixture authorization record disappeared".into())
        })?;
        record.state = match state {
            PaymentAuthorizationState::Held => PaymentObservation::Held(authorization.clone()),
            PaymentAuthorizationState::PrepaidFinal => PaymentObservation::Settled {
                authorization: authorization.clone(),
                result: PaymentResult {
                    transaction_id: authorization.authorization_id.clone(),
                    settlement_status: RailSettlementStatus::Settled,
                    metadata: serde_json::json!({}),
                },
            },
        };
        Ok(authorization)
    }

    fn observe(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let records = self.records()?;
        let Some(record) = records.get(reference) else {
            return if authorization_id.is_some() {
                Err(PaymentError::RailError(
                    "fixture authorization has no matching reference".into(),
                ))
            } else {
                Ok(RailSettlementState::NoAuthorization)
            };
        };
        let authorization = record.state.authorization().ok_or_else(|| {
            PaymentError::Unavailable("fixture authorization is in progress".into())
        })?;
        if authorization_id.is_some_and(|id| id != authorization.authorization_id) {
            return Err(PaymentError::RailError(
                "fixture authorization does not match reference".into(),
            ));
        }
        match &record.state {
            PaymentObservation::Held(authorization) => Ok(RailSettlementState::Held {
                authorization_id: authorization.authorization_id.clone(),
            }),
            PaymentObservation::Settled {
                authorization,
                result,
            } => Ok(RailSettlementState::Settled {
                authorization_id: authorization.authorization_id.clone(),
                result: result.clone(),
            }),
            PaymentObservation::Authorizing => Err(PaymentError::Unavailable(
                "fixture authorization is in progress".into(),
            )),
        }
    }

    fn terminal(
        &self,
        reference: &str,
        authorization_id: &str,
        operation: TerminalOperation,
    ) -> Result<PaymentResult, PaymentError> {
        let mut records = self.records()?;
        let record = records.get_mut(reference).ok_or_else(|| {
            PaymentError::RailError("fixture terminal has no matching reference".into())
        })?;
        let authorization = record.state.authorization().cloned().ok_or_else(|| {
            PaymentError::Unavailable("fixture authorization is in progress".into())
        })?;
        if authorization.authorization_id != authorization_id {
            return Err(PaymentError::RailError(
                "fixture terminal authorization changed".into(),
            ));
        }
        if let Some((previous, result)) = record.terminal_operations.iter().find(|(previous, _)| {
            std::mem::discriminant(previous) == std::mem::discriminant(&operation)
        }) {
            if previous != &operation {
                return Err(PaymentError::RailError(
                    "fixture terminal request changed".into(),
                ));
            }
            return Ok(result.clone());
        }
        if let TerminalOperation::Capture {
            amount_units,
            currency,
        }
        | TerminalOperation::Refund {
            amount_units,
            currency,
        } = &operation
        {
            if *amount_units > record.request.amount_units || *currency != record.request.currency {
                return Err(PaymentError::RailError(
                    "fixture terminal exceeds its authorization".into(),
                ));
            }
        }
        let compatible = match (&record.state, &operation) {
            (
                PaymentObservation::Held(_),
                TerminalOperation::Capture { .. } | TerminalOperation::Release,
            ) => true,
            (PaymentObservation::Settled { result, .. }, TerminalOperation::Refund { .. }) => {
                result.settlement_status == RailSettlementStatus::Settled
            }
            (
                PaymentObservation::Settled {
                    authorization,
                    result,
                },
                TerminalOperation::Capture { .. },
            ) => {
                authorization.state == PaymentAuthorizationState::PrepaidFinal
                    && result.settlement_status == RailSettlementStatus::Settled
            }
            _ => false,
        };
        if !compatible {
            return Err(PaymentError::RailError(
                "fixture terminal conflicts with the observed rail state".into(),
            ));
        }
        let (transaction_id, settlement_status) = match operation {
            TerminalOperation::Capture { .. } => {
                self.captures.fetch_add(1, Ordering::SeqCst);
                (authorization_id.to_owned(), RailSettlementStatus::Settled)
            }
            TerminalOperation::Release => {
                self.releases.fetch_add(1, Ordering::SeqCst);
                (
                    format!("release:{authorization_id}"),
                    RailSettlementStatus::Released,
                )
            }
            TerminalOperation::Refund { .. } => {
                (authorization_id.to_owned(), RailSettlementStatus::Refunded)
            }
        };
        let result = PaymentResult {
            transaction_id,
            settlement_status,
            metadata: serde_json::json!({}),
        };
        record.state = PaymentObservation::Settled {
            authorization,
            result: result.clone(),
        };
        record.terminal_operations.push((operation, result.clone()));
        Ok(result)
    }
}

pub(super) struct ReversibleHoldAdapter {
    pub(super) calls: Arc<PaymentCalls>,
    pub(super) authorize_hook: Option<Arc<dyn Fn() -> Result<(), String> + Send + Sync>>,
}

impl PaymentAdapter for ReversibleHoldAdapter {
    fn rail_id(&self) -> &'static str {
        "wedge-reversible-hold"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.calls.authorize(
            request,
            PaymentAuthorizationState::Held,
            "authorization",
            self.authorize_hook.as_deref(),
        )
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.terminal(
            reference,
            authorization_id,
            TerminalOperation::Capture {
                amount_units,
                currency: currency.to_owned(),
            },
        )
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls
            .terminal(reference, authorization_id, TerminalOperation::Release)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.terminal(
            reference,
            transaction_id,
            TerminalOperation::Refund {
                amount_units,
                currency: currency.to_owned(),
            },
        )
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.calls.observe(reference, authorization_id)
    }
}

/// A final-settlement rail: it prepays, so it cannot arbitrate a compare
/// that only runs after the tool returns.
pub(super) struct PrepaidFinalAdapter {
    pub(super) calls: Arc<PaymentCalls>,
}

impl PaymentAdapter for PrepaidFinalAdapter {
    fn rail_id(&self) -> &'static str {
        "wedge-prepaid-final"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.calls.authorize(
            request,
            PaymentAuthorizationState::PrepaidFinal,
            "prepaid",
            None,
        )
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.terminal(
            reference,
            authorization_id,
            TerminalOperation::Capture {
                amount_units,
                currency: currency.to_owned(),
            },
        )
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls
            .terminal(reference, authorization_id, TerminalOperation::Release)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.terminal(
            reference,
            transaction_id,
            TerminalOperation::Refund {
                amount_units,
                currency: currency.to_owned(),
            },
        )
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.calls.observe(reference, authorization_id)
    }
}
