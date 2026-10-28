use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedTransactionIntent,
};
use chio_core::crypto::PublicKey;
use chio_security_types::clock::{AuthorityDeadline, Clock, UnixMillis};

use crate::{ApprovalBinding, SettlementError};

mod replay;
pub use replay::{ApprovalReplayOutcome, ApprovalReplayStore, InMemoryApprovalReplayStore};

const MAX_BINDING_BYTES: usize = 4096;
const MAX_APPROVAL_TTL_SECONDS: u64 = 3600;

pub struct VerifiedApproval {
    binding: ApprovalBinding,
    request_id: String,
    intent_hash: String,
    expires_at_unix_ms: u64,
    deadline: AuthorityDeadline,
    clock: Arc<dyn Clock>,
    replay: Arc<dyn ApprovalReplayStore>,
}

impl std::fmt::Debug for VerifiedApproval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedApproval")
            .finish_non_exhaustive()
    }
}

impl VerifiedApproval {
    pub(crate) fn binding(&self) -> &ApprovalBinding {
        &self.binding
    }

    pub(crate) fn check_time(&mut self) -> Result<(), SettlementError> {
        self.deadline.remaining(self.clock.read()?)?;
        Ok(())
    }

    pub(crate) fn consume(mut self) -> Result<(), SettlementError> {
        let now = self.clock.read()?;
        self.deadline.remaining(now)?;
        match self.replay.record_if_fresh(
            &self.request_id,
            &self.intent_hash,
            self.expires_at_unix_ms,
            now.unix_millis().get(),
        )? {
            ApprovalReplayOutcome::Fresh => Ok(()),
            ApprovalReplayOutcome::Replayed => Err(refused("settlement approval already consumed")),
        }
    }
}

pub fn verify_governed_approval(
    token: &GovernedApprovalToken,
    intent: &GovernedTransactionIntent,
    expected_approver: &PublicKey,
    expected_subject: &PublicKey,
    expected_request_id: &str,
    clock: Arc<dyn Clock>,
    replay: Arc<dyn ApprovalReplayStore>,
) -> Result<VerifiedApproval, SettlementError> {
    if token.approver != *expected_approver {
        return Err(refused("settlement approval approver mismatch"));
    }
    let signature_valid = expected_approver
        .verify_canonical(&token.body(), &token.signature)
        .map_err(|_| refused("settlement approval signature malformed"))?;
    if !signature_valid {
        return Err(refused("settlement approval signature invalid"));
    }
    if token.decision != GovernedApprovalDecision::Approved {
        return Err(refused("settlement approval decision denied"));
    }
    if token.subject != *expected_subject {
        return Err(refused("settlement approval subject mismatch"));
    }
    if token.request_id != expected_request_id || !valid_identifier(expected_request_id) {
        return Err(refused("settlement approval request mismatch"));
    }
    let hash = intent
        .binding_hash()
        .map_err(|_| refused("settlement intent encoding failed"))?;
    if hash != token.governed_intent_hash {
        return Err(refused("settlement approval intent mismatch"));
    }
    let lifetime = token
        .expires_at
        .checked_sub(token.issued_at)
        .ok_or(chio_security_types::clock::ClockError::InvalidWindow)?;
    if lifetime > MAX_APPROVAL_TTL_SECONDS {
        return Err(refused("settlement approval lifetime exceeds 3600 seconds"));
    }
    let expires_at = UnixMillis::from_secs(token.expires_at)?;
    let deadline = AuthorityDeadline::new(
        UnixMillis::from_secs(token.issued_at)?,
        expires_at,
        clock.read()?,
    )?;
    let value = intent
        .context
        .as_ref()
        .and_then(|context| context.get("chioSettlementBinding"))
        .filter(|value| !value.is_null())
        .ok_or_else(|| refused("settlement approval requires a signed settlement binding"))?;
    let bytes =
        canonical_json_bytes(value).map_err(|_| refused("settlement binding encoding failed"))?;
    let binding: ApprovalBinding = crate::input::canonical(&bytes, MAX_BINDING_BYTES)?;
    validate_binding(&binding)?;
    if let Some(maximum) = &intent.max_amount {
        if !maximum
            .currency
            .eq_ignore_ascii_case(&binding.settlement_currency)
        {
            return Err(refused("settlement binding maximum currency mismatch"));
        }
        if binding.amount_minor_units > u128::from(maximum.units) {
            return Err(refused(
                "settlement binding exceeds the signed maximum amount",
            ));
        }
    }
    Ok(VerifiedApproval {
        binding,
        request_id: token.request_id.clone(),
        intent_hash: hash,
        expires_at_unix_ms: expires_at.get(),
        deadline,
        clock,
        replay,
    })
}

fn validate_binding(binding: &ApprovalBinding) -> Result<(), SettlementError> {
    if binding.schema != "chio.settlement-binding.v1" {
        return Err(refused("settlement binding schema mismatch"));
    }
    if binding.chain_id == 0 {
        return Err(refused("settlement binding chain malformed"));
    }
    if binding
        .payee_address
        .parse::<alloy_primitives::Address>()
        .is_err()
    {
        return Err(refused("settlement binding payee malformed"));
    }
    if let Some(contract) = &binding.token_contract {
        if contract.parse::<alloy_primitives::Address>().is_err() {
            return Err(refused("settlement binding token contract malformed"));
        }
    }
    if !valid_identifier(&binding.dispatch_id) {
        return Err(refused("settlement binding dispatch id malformed"));
    }
    if !valid_identifier(&binding.capability_id) {
        return Err(refused("settlement binding capability id malformed"));
    }
    for symbol in [&binding.token_symbol, &binding.settlement_currency] {
        if symbol.is_empty()
            || symbol.len() > 16
            || !symbol.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(refused("settlement binding currency malformed"));
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn refused(reason: &str) -> SettlementError {
    SettlementError::Verification(reason.to_string())
}
