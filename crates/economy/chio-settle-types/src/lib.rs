//! Settlement vocabulary shared by the Chio kernel, stores and settlement
//! runtime: observer hook contracts, leased outcome claims, retry policy,
//! completion-flow row ids and the channel receipt-authority digest.
//!
//! The crate depends only on `chio-core-types` and `chio-security-types`, so
//! no chain, web3 or finding-market crate enters a consumer's closure.

#![forbid(unsafe_code)]

mod channel;
mod hook;
mod outcome_store;
mod retry;

pub use channel::{derive_channel_receipt_authority_digest, ChannelReceiptAuthorityDigestError};
pub use hook::{
    ObservedSettlement, SettlementFailureClass, SettlementFailureCode,
    SettlementFailureCodeParseError, SettlementFailureReason, SettlementHook, SettlementHookError,
    SettlementIdempotencyKey, SettlementObservation, SettlementOutcome, SettlementSkipReason,
    SETTLEMENT_OBSERVATION_SCHEMA, SETTLEMENT_OUTCOME_SCHEMA,
};
pub use outcome_store::{
    validate_settlement_claim, SettlementAttemptClaim, SettlementClaimValidationError,
    SettlementOutcomeStore, SettlementRoute, SettlementRouteError, SettlementRouteErrorClass,
    SettlementRoutingInput, SettlementStoreBinding, MAX_SETTLEMENT_CLAIM_BATCH,
    MAX_SETTLEMENT_LEASE_MS, MAX_SETTLEMENT_WORKER_ID_BYTES,
};
pub use retry::{
    classify_attempt, DeadLetterRecord, RetryDecision, RetryPolicy, RetryPolicyError,
    DEFAULT_BACKOFF_CAP_MS, DEFAULT_BACKOFF_MULTIPLIER, DEFAULT_INITIAL_BACKOFF_MS,
    DEFAULT_MAX_RETRIES, SETTLE_DEAD_LETTER_SCHEMA,
};

pub const SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX: &str = "economic-completion-flow:";

pub fn settlement_completion_flow_row_id(receipt_id: &str) -> Result<String, SettlementError> {
    if receipt_id.trim().is_empty() {
        return Err(SettlementError::invalid_input(
            "completion-flow binding requires a non-empty receipt id",
        ));
    }
    if receipt_id.trim() != receipt_id {
        return Err(SettlementError::invalid_input(
            "completion-flow receipt id must not contain surrounding whitespace",
        ));
    }
    Ok(format!(
        "{SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX}{receipt_id}"
    ))
}

pub fn settlement_completion_flow_receipt_id(row_id: &str) -> Result<&str, SettlementError> {
    let receipt_id = row_id
        .strip_prefix(SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX)
        .ok_or_else(|| {
            SettlementError::invalid_input(format!(
                "completion-flow row id `{row_id}` does not carry the expected prefix"
            ))
        })?;
    if receipt_id.trim().is_empty() {
        return Err(SettlementError::invalid_input(format!(
            "completion-flow row id `{row_id}` does not carry the expected prefix"
        )));
    }
    if receipt_id.trim() != receipt_id {
        return Err(SettlementError::invalid_input(
            "completion-flow row id receipt id must not contain surrounding whitespace",
        ));
    }
    Ok(receipt_id)
}

#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error("invalid settlement input: {0}")]
    Input(#[from] chio_core_types::canonical::SharedUntrustedJsonError),
    #[error("settlement file read failed")]
    Io(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid dispatch: {0}")]
    InvalidDispatch(String),

    #[error("invalid binding: {0}")]
    InvalidBinding(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("verification error: {0}")]
    Verification(String),
}

impl SettlementError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        settlement_completion_flow_receipt_id, settlement_completion_flow_row_id, SettlementError,
        SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX,
    };

    use chio_test_support::prelude::*;

    #[test]
    fn invalid_input_constructor_preserves_message() {
        let error = SettlementError::invalid_input("rpc_url must not be empty");
        assert!(matches!(
            error,
            SettlementError::InvalidInput(message) if message == "rpc_url must not be empty"
        ));
    }

    #[test]
    fn completion_flow_receipt_ids_reject_surrounding_whitespace() {
        let error = settlement_completion_flow_row_id(" receipt-1")
            .test_expect_err("padded receipt id rejected when building row id");
        assert!(error.to_string().contains("surrounding whitespace"));

        let row_id = format!("{SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX}receipt-1 ");
        let error = settlement_completion_flow_receipt_id(&row_id)
            .test_expect_err("padded receipt id rejected when parsing row id");
        assert!(error.to_string().contains("surrounding whitespace"));
    }
}
