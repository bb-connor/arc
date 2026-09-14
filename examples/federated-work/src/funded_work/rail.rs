use super::{
    agreement::Policy,
    journal::Journal,
    native::{CURRENCY, SERVER},
    observer::{self, FundingSource},
};
use crate::common::{digest, now, Result};
use chio_kernel::{
    admission_operation::{AdmissionOperationId, AdmissionOperationStore, StoreMutationFence},
    payment::*,
};
use chio_store_sqlite::SqliteAdmissionOperationStore;
use std::sync::Arc;

pub const RAIL: &str = "experimental-claim-allocation-v1";

pub struct FundingRail {
    pub journal: Arc<Journal>,
    pub operations: SqliteAdmissionOperationStore,
    pub fence: StoreMutationFence,
    pub policy: Policy,
    pub source: Arc<dyn FundingSource>,
    pub checkpoint: super::Checkpoint,
}

struct VerifiedAuthorization {
    allocation: String,
    hold: String,
    authorization: PaymentAuthorization,
}

pub fn authorization_id(allocation: &str) -> Result<String> {
    let id = super::allocation::hash(allocation)?;
    Ok(format!("funded-{}", alloy_primitives::hex::encode(id)))
}

impl FundingRail {
    // This phase has no rail side effects. A failure is a definite refusal;
    // only the subsequent journal commit can have an ambiguous outcome.
    fn verify_original(&self, request: &PaymentAuthorizeRequest) -> Result<VerifiedAuthorization> {
        let operation_id = AdmissionOperationId::from_persisted(&request.reference)?;
        let time = now()?;
        let (operation, retained) = self
            .operations
            .load_retained_tool_request(&operation_id, &self.fence, super::now_ms()?)?
            .ok_or("native funding operation lacks retained request")?;
        let binding = operation.binding();
        let entry = self
            .journal
            .by_request(binding.request_id().as_str())?
            .ok_or("no verified funding for native request")?;
        let terms = entry.agreement.validate(&self.policy, &entry.request)?;
        let original = retained.request_for_revalidation();
        if digest(original)? != digest(&entry.request)?
            || binding.coordinator_authority_id().as_str() != self.policy.authority_uuid
            || binding.policy_hash().as_str() != digest(&self.policy)?
            || request.amount_units != 100
            || request.currency != CURRENCY
            || request.payer != self.policy.buyer_key.to_hex()
            || request.payee != SERVER
            || request.governed.is_some()
            || request.commerce.is_some()
        {
            return Err("payment request does not match original funded native operation".into());
        }
        let payment = self
            .operations
            .load_payment_journal(&request.reference, &self.fence)?
            .ok_or("native payment journal missing")?;
        if payment.rail != RAIL
            || payment.request_id != original.request_id
            || payment.capability_id != original.capability.id
            || payment.amount_units != 100
            || payment.currency != CURRENCY
            || payment.request_namespace_digest != binding.request_namespace_digest().as_str()
        {
            return Err("funding changed native payment journal".into());
        }
        let observed = self.source.observe(&entry.allocation)?;
        let verified = observer::verify(&self.policy.domain, &terms, &observed, time, now()?)?;
        if verified.id != entry.allocation {
            return Err("funding allocation changed at authorization".into());
        }
        let hold = payment
            .hold_id
            .as_deref()
            .ok_or("native budget hold missing")?;
        Ok(VerifiedAuthorization {
            allocation: entry.allocation.clone(),
            hold: hold.to_owned(),
            authorization: PaymentAuthorization {
                authorization_id: authorization_id(&entry.allocation)?,
                state: PaymentAuthorizationState::Held,
                metadata: serde_json::json!({"allocationId": entry.allocation, "nativeHoldId": hold,
                "fundingObservationSha256": verified.observation_digest, "observedAt": verified.observed_at,
                "externalFundsTransferred": false, "profile": observer::PROFILE}),
            },
        })
    }
}

impl PaymentAdapter for FundingRail {
    fn rail_id(&self) -> &'static str {
        RAIL
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> std::result::Result<PaymentAuthorization, PaymentError> {
        let verified = self
            .verify_original(request)
            .map_err(|error| PaymentError::Declined(error.to_string()))?;
        (self.checkpoint)("before-bind")
            .map_err(|error| PaymentError::Declined(error.to_string()))?;
        self.journal
            .bind(&verified.allocation, &request.reference, &verified.hold)
            .map_err(|error| PaymentError::Unavailable(error.to_string()))?;
        (self.checkpoint)("after-hold")
            .map_err(|error| PaymentError::Unavailable(error.to_string()))?;
        Ok(verified.authorization)
    }
    fn capture(
        &self,
        _id: &str,
        _amount: u64,
        _currency: &str,
        _reference: &str,
    ) -> std::result::Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable(
            "claim decision and ERC20 withdrawal have not been observed".into(),
        ))
    }
    fn release(
        &self,
        _id: &str,
        _reference: &str,
    ) -> std::result::Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable(
            "allocation refund has not been observed".into(),
        ))
    }
    fn refund(
        &self,
        _id: &str,
        _amount: u64,
        _currency: &str,
        _reference: &str,
    ) -> std::result::Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable(
            "allocation refund has not been observed".into(),
        ))
    }
    fn settlement_state(
        &self,
        reference: &str,
        id: Option<&str>,
    ) -> std::result::Result<RailSettlementState, PaymentError> {
        let state = || -> Result<RailSettlementState> {
            let Some(entry) = self.journal.by_operation(reference)? else {
                return if id.is_none() {
                    Ok(RailSettlementState::NoAuthorization)
                } else {
                    Err("known authorization is absent from funding journal".into())
                };
            };
            entry.agreement.validate(&self.policy, &entry.request)?;
            let terms = entry.agreement.body.terms()?;
            if entry.allocation
                != super::allocation::allocation_id(
                    &self.policy.domain.chain_id,
                    &self.policy.domain.escrow,
                    &terms,
                )?
            {
                return Err("persisted funding allocation identity changed".into());
            }
            let authorization = authorization_id(&entry.allocation)?;
            if id.is_some_and(|id| id != authorization) {
                return Err("funding authorization identity changed".into());
            }
            Ok(RailSettlementState::Held {
                authorization_id: authorization,
            })
        };
        state().map_err(|error| PaymentError::Unavailable(error.to_string()))
    }
}
