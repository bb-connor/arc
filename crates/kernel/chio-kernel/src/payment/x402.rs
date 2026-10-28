//! x402 facilitator rail.
//!
//! Protocol: x402 v2 (`x402Version: 2`), `exact` scheme on EVM networks, where
//! the payer's `PaymentPayload` carries a signed EIP-3009
//! `transferWithAuthorization`. The adapter calls the facilitator's
//! `POST /verify` and then `POST /settle` with
//! `{ x402Version, paymentPayload, paymentRequirements }` before the tool runs,
//! so every authorization is a final prepayment.
//!
//! Before contacting the facilitator the adapter checks the EIP-3009 validity
//! window against its injected trusted clock and refuses an authorization key
//! (network, asset, payer, nonce) its durable replay store already holds. The
//! key is reserved after `/verify` and before `/settle`, the first call that
//! can broadcast, so a verification refusal leaves the nonce unspent and a
//! settlement of any outcome consumes it permanently.
//!
//! The adapter holds no keys and never broadcasts. It has no rail status
//! query: `settlement_state` answers `Unavailable`, so a settlement whose
//! acknowledgement was lost ends in `ReconcileFailed` and a dead letter for the
//! operator. A facilitator `settlement_pending` answer is outcome-unknown and
//! carries the broadcast transaction so the operator can reconcile on chain.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chio_core::{canonical_json_bytes, sha256};
use chio_security_types::clock::Clock;
use serde::{Deserialize, Serialize};

use super::{
    payment_identifier_is_valid, post_json, validate_payment_endpoint, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest, PaymentError,
    PaymentRailMode, PaymentResult, RailSettlementState, RailSettlementStatus, X402SettlementRef,
};
use crate::execution_nonce::ExecutionNonceStore;
use crate::KernelError;

/// x402 protocol version this adapter speaks.
pub const X402_VERSION: u8 = 2;
/// The only x402 scheme this adapter accepts.
pub const X402_EXACT_SCHEME: &str = "exact";

const X402_VERIFY_PATH: &str = "/verify";
const X402_SETTLE_PATH: &str = "/settle";
const X402_AUTHORIZATION_ID_PREFIX: &str = "x402";
/// Non-terminal settle `errorReason`: broadcast, confirmation not established.
const X402_SETTLEMENT_PENDING: &str = "settlement_pending";
const MAX_X402_SIGNATURE_HEX_BYTES: usize = 4096;
/// Retention horizon, in Unix seconds, of a spent authorization key. The token
/// contract consumes an EIP-3009 nonce permanently, whatever `validBefore` the
/// payer signed, so the local marker outlives every authorization that can
/// carry it and is never pruned; a full store refuses new nonces instead. The
/// value stays representable in Unix milliseconds and leaves headroom for a
/// store's retention grace.
const X402_NONCE_RETAINED_UNTIL: i64 = i64::MAX / 1_000;

/// CAIP-2 networks the x402 rail may settle on. On-chain value stays
/// rehearsal-only: Base Sepolia.
const X402_TESTNET_ALLOWLIST: &[&str] = &["eip155:84532"];

/// Why the x402 adapter refused a payment before any settlement was attempted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum X402Refusal {
    #[error("x402 network is not on the testnet allowlist")]
    NetworkNotAllowlisted,
    #[error("x402 rail configuration is invalid")]
    InvalidRailConfig,
    #[error("x402 payment requires a durable admission reference")]
    DurableReferenceRequired,
    #[error("x402 charge is not denominated in the token base unit")]
    UnitMismatch,
    #[error("x402 payment was not presented")]
    PaymentMissing,
    #[error("x402 payment uses an unsupported protocol version")]
    UnsupportedVersion,
    #[error("x402 payment uses an unsupported scheme")]
    UnsupportedScheme,
    #[error("x402 payment does not echo the issued requirements")]
    RequirementsMismatch,
    #[error("x402 payment does not match the configured rail")]
    RailMismatch,
    #[error("x402 payment amount does not match the charge")]
    AmountMismatch,
    #[error("x402 authorization is malformed")]
    MalformedAuthorization,
    #[error("x402 authorization outlives its capability or approval")]
    OutlivesAuthority,
    #[error("x402 authority expiry is unknown")]
    AuthorityExpiryMissing,
    /// EIP-3009 accepts an authorization only once `now > validAfter`.
    #[error("x402 authorization is not valid until after {valid_after} (now {now})")]
    NotYetValid { now: u64, valid_after: u64 },
    /// EIP-3009 refuses an authorization once `now >= validBefore`.
    #[error("x402 authorization expired at {valid_before} (now {now})")]
    Expired { now: u64, valid_before: u64 },
    #[error("x402 authorization nonce was already used")]
    NonceReused,
    #[error("x402 replay store has no capacity for another nonce")]
    ReplayCapacityExhausted,
    #[error("x402 facilitator rejected the payment")]
    VerifyRejected,
    #[error("x402 facilitator verification failed")]
    VerifyFailed,
}

impl From<X402Refusal> for PaymentError {
    fn from(refusal: X402Refusal) -> Self {
        Self::Declined(refusal.to_string())
    }
}

/// A CAIP-2 network that passed the x402 testnet allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402Network(String);

impl X402Network {
    pub fn allowlisted(caip2: &str) -> Result<Self, X402Refusal> {
        if X402_TESTNET_ALLOWLIST.contains(&caip2) {
            Ok(Self(caip2.to_owned()))
        } else {
            Err(X402Refusal::NetworkNotAllowlisted)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Highest ERC-20 `decimals` value the rail accepts.
const MAX_X402_TOKEN_DECIMALS: u8 = 36;

/// Operator-configured rail the adapter settles to. Chio charges on this rail
/// are denominated in the token's base unit: the charge currency is the token
/// symbol and one charge unit is `10^-token_decimals` of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402RailConfig {
    pub network: X402Network,
    /// EIP-3009 token contract, lowercase `0x` hex.
    pub asset: String,
    /// Token symbol, which is also the Chio charge currency on this rail.
    pub token_symbol: String,
    /// ERC-20 `decimals` of the token.
    pub token_decimals: u8,
    /// Payee address, lowercase `0x` hex.
    pub pay_to: String,
}

impl X402RailConfig {
    pub fn new(
        network: X402Network,
        asset: &str,
        token_symbol: &str,
        token_decimals: u8,
        pay_to: &str,
    ) -> Result<Self, X402Refusal> {
        let asset = evm_address(asset).ok_or(X402Refusal::InvalidRailConfig)?;
        let pay_to = evm_address(pay_to).ok_or(X402Refusal::InvalidRailConfig)?;
        if token_symbol.is_empty()
            || !token_symbol
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            || token_decimals > MAX_X402_TOKEN_DECIMALS
        {
            return Err(X402Refusal::InvalidRailConfig);
        }
        Ok(Self {
            network,
            asset,
            token_symbol: token_symbol.to_owned(),
            token_decimals,
            pay_to,
        })
    }
}

/// x402 v2 `PaymentRequirements` for the `exact` scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct X402PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Signed EIP-3009 authorization inside an `exact` EVM payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct X402Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct X402ExactEvmPayload {
    pub signature: String,
    pub authorization: X402Eip3009Authorization,
}

/// x402 v2 `PaymentPayload` the payer presented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct X402PaymentPayload {
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<serde_json::Value>,
    pub accepted: X402PaymentRequirements,
    pub payload: X402ExactEvmPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// The payment presented for one request together with the requirements
/// Chio issued for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402PaymentContext {
    pub payment_payload: X402PaymentPayload,
    pub payment_requirements: X402PaymentRequirements,
}

/// Rail coordinates that identify one x402 prepayment on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct X402AuthorizationIdentity {
    network: String,
    asset: String,
    from: String,
    nonce: String,
    valid_before: u64,
}

impl X402AuthorizationIdentity {
    /// Single-use key of the EIP-3009 authorization: the token contract
    /// tracks `(authorizer, nonce)`, scoped here by network and asset.
    fn replay_key(&self) -> String {
        format!(
            "{X402_AUTHORIZATION_ID_PREFIX}/{}/{}/{}/{}",
            self.network, self.asset, self.from, self.nonce
        )
    }
}

impl fmt::Display for X402AuthorizationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{X402_AUTHORIZATION_ID_PREFIX}/{}/{}/{}/{}/{}",
            self.network, self.asset, self.from, self.nonce, self.valid_before
        )
    }
}

/// A settled x402 prepayment: its rail coordinates, the settlement
/// transaction and the digests that bind it. Rendered as
/// `x402/<caip2>/<asset>/<from>/<nonce>/<validBefore>/<transaction>/<payloadDigest>/<responseDigest>`
/// and used as the authorization identifier, so the durable journal holds
/// the whole settlement reference and a replay restores it without the rail.
#[derive(Debug, Clone, PartialEq, Eq)]
struct X402SettledAuthorization {
    identity: X402AuthorizationIdentity,
    transaction: String,
    payment_payload_digest: String,
    settlement_response_digest: String,
}

impl fmt::Display for X402SettledAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}/{}/{}",
            self.identity,
            self.transaction,
            self.payment_payload_digest,
            self.settlement_response_digest
        )
    }
}

impl X402SettledAuthorization {
    fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('/').collect();
        let [prefix, network, asset, from, nonce, before, transaction, payload_digest, response_digest] =
            parts.as_slice()
        else {
            return None;
        };
        if *prefix != X402_AUTHORIZATION_ID_PREFIX {
            return None;
        }
        X402Network::allowlisted(network).ok()?;
        let settled = Self {
            identity: X402AuthorizationIdentity {
                network: (*network).to_owned(),
                asset: evm_address(asset)?,
                from: evm_address(from)?,
                nonce: bytes32(nonce)?,
                valid_before: decimal_u64(before)?,
            },
            transaction: bytes32(transaction)?,
            payment_payload_digest: sha256_hex(payload_digest)?,
            settlement_response_digest: sha256_hex(response_digest)?,
        };
        (settled.to_string() == value).then_some(settled)
    }

    fn settlement_ref(&self) -> X402SettlementRef {
        X402SettlementRef {
            x402_version: X402_VERSION,
            scheme: X402_EXACT_SCHEME.to_owned(),
            network: self.identity.network.clone(),
            transaction: self.transaction.clone(),
            payer: self.identity.from.clone(),
            payment_payload_digest: self.payment_payload_digest.clone(),
            settlement_response_digest: self.settlement_response_digest.clone(),
        }
    }

    fn authorization_metadata(&self) -> Result<serde_json::Value, PaymentError> {
        let x402 = serde_json::to_value(self.settlement_ref()).map_err(|error| {
            PaymentError::RailError(format!("x402 settlement reference is invalid: {error}"))
        })?;
        Ok(serde_json::json!({
            "adapter": "x402",
            "mode": "prepaid",
            "x402": x402,
        }))
    }
}

/// x402 v2 facilitator adapter. Final prepayment only: there is no hold to
/// release and no remote refund.
#[derive(Clone)]
pub struct X402PaymentAdapter {
    facilitator_url: String,
    rail: X402RailConfig,
    bearer_token: Option<String>,
    timeout: Duration,
    clock: Arc<dyn Clock>,
    replay: Arc<dyn ExecutionNonceStore>,
}

impl fmt::Debug for X402PaymentAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X402PaymentAdapter")
            .field("facilitator_url", &self.facilitator_url)
            .field("rail", &self.rail)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

impl X402PaymentAdapter {
    /// Refuses a facilitator URL that is not `https` or loopback `http`, that
    /// carries credentials, a query or a fragment, whose host is a private,
    /// link-local or unique-local address literal, or that names a loopback
    /// host over `https`. A hostname that resolves to a private, loopback,
    /// link-local or unique-local address is refused when a request connects.
    /// `clock` is the
    /// trusted time the validity window is checked against; `replay` holds
    /// each accepted authorization key until its `validBefore` and must be
    /// durable for single use to survive a restart.
    pub fn new(
        facilitator_url: impl Into<String>,
        rail: X402RailConfig,
        clock: Arc<dyn Clock>,
        replay: Arc<dyn ExecutionNonceStore>,
    ) -> Result<Self, PaymentError> {
        let facilitator_url = facilitator_url.into().trim_end_matches('/').to_string();
        validate_payment_endpoint(&facilitator_url, X402_VERIFY_PATH, None)?;
        Ok(Self {
            facilitator_url,
            rail,
            bearer_token: None,
            timeout: super::PAYMENT_RAIL_TIMEOUT,
            clock,
            replay,
        })
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn check_payment(
        &self,
        request: &PaymentAuthorizeRequest,
        context: &X402PaymentContext,
        now: u64,
    ) -> Result<(X402AuthorizationIdentity, u64), X402Refusal> {
        if !request.reference_is_durable {
            return Err(X402Refusal::DurableReferenceRequired);
        }
        let payload = &context.payment_payload;
        let requirements = &context.payment_requirements;
        if payload.x402_version != X402_VERSION {
            return Err(X402Refusal::UnsupportedVersion);
        }
        if requirements.scheme != X402_EXACT_SCHEME {
            return Err(X402Refusal::UnsupportedScheme);
        }
        if payload.accepted != *requirements {
            return Err(X402Refusal::RequirementsMismatch);
        }
        X402Network::allowlisted(&requirements.network)?;
        if requirements.network != self.rail.network.as_str()
            || evm_address(&requirements.asset).as_deref() != Some(self.rail.asset.as_str())
            || evm_address(&requirements.pay_to).as_deref() != Some(self.rail.pay_to.as_str())
            || requirements.max_timeout_seconds == 0
        {
            return Err(X402Refusal::RailMismatch);
        }
        if request.currency != self.rail.token_symbol {
            return Err(X402Refusal::UnitMismatch);
        }
        let authorization = &payload.payload.authorization;
        let (Some(from), Some(to), Some(nonce), Some(value), Some(valid_after), Some(valid_before)) = (
            evm_address(&authorization.from),
            evm_address(&authorization.to),
            bytes32(&authorization.nonce),
            decimal_u64(&authorization.value),
            decimal_u64(&authorization.valid_after),
            decimal_u64(&authorization.valid_before),
        ) else {
            return Err(X402Refusal::MalformedAuthorization);
        };
        if valid_after >= valid_before || !signature_is_well_formed(&payload.payload.signature) {
            return Err(X402Refusal::MalformedAuthorization);
        }
        if to != self.rail.pay_to {
            return Err(X402Refusal::RailMismatch);
        }
        if decimal_u64(&requirements.amount) != Some(request.amount_units)
            || value != request.amount_units
        {
            return Err(X402Refusal::AmountMismatch);
        }
        let authority_expires_at = request
            .authority_expires_at
            .ok_or(X402Refusal::AuthorityExpiryMissing)?;
        if valid_before > authority_expires_at {
            return Err(X402Refusal::OutlivesAuthority);
        }
        check_window(now, valid_after, valid_before)?;
        let identity = X402AuthorizationIdentity {
            network: self.rail.network.as_str().to_owned(),
            asset: self.rail.asset.clone(),
            from,
            nonce,
            valid_before,
        };
        Ok((identity, valid_after))
    }

    fn now_unix_secs(&self) -> Result<u64, PaymentError> {
        self.clock
            .unix_millis()
            .map(|now| now.as_secs())
            .map_err(|_| PaymentError::Unavailable("x402 trusted clock is unavailable".to_owned()))
    }

    fn ensure_unspent(&self, identity: &X402AuthorizationIdentity) -> Result<(), PaymentError> {
        match self.replay.is_consumed(&identity.replay_key()) {
            Ok(false) => Ok(()),
            Ok(true) => Err(X402Refusal::NonceReused.into()),
            Err(_) => Err(replay_store_unavailable()),
        }
    }

    /// Consumes the authorization key. Called after `/verify` with a fresh
    /// clock reading, because the verification round trip may cross the
    /// authorization's expiry.
    fn spend(
        &self,
        identity: &X402AuthorizationIdentity,
        valid_after: u64,
    ) -> Result<(), PaymentError> {
        check_window(self.now_unix_secs()?, valid_after, identity.valid_before)?;
        match self
            .replay
            .reserve_until(&identity.replay_key(), X402_NONCE_RETAINED_UNTIL)
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(X402Refusal::NonceReused.into()),
            Err(KernelError::ExecutionNonceCapacity) => {
                Err(X402Refusal::ReplayCapacityExhausted.into())
            }
            Err(_) => Err(replay_store_unavailable()),
        }
    }

    fn verify(&self, body: &X402FacilitatorRequest<'_>) -> Result<(), X402Refusal> {
        let response: X402VerifyResponse = post_json(
            self.timeout,
            &self.facilitator_url,
            self.bearer_token.as_deref(),
            X402_VERIFY_PATH,
            body,
        )
        .map_err(|_| X402Refusal::VerifyFailed)?;
        if !response.is_valid {
            return Err(X402Refusal::VerifyRejected);
        }
        Ok(())
    }

    fn settle(
        &self,
        body: &X402FacilitatorRequest<'_>,
        identity: &X402AuthorizationIdentity,
    ) -> Result<X402SettledAuthorization, PaymentError> {
        let response: X402SettleResponse = post_json(
            self.timeout,
            &self.facilitator_url,
            self.bearer_token.as_deref(),
            X402_SETTLE_PATH,
            body,
        )
        .map_err(|error| match error {
            PaymentError::Unavailable(_) => {
                PaymentError::Unavailable("x402 facilitator settlement is unavailable".to_owned())
            }
            _ => PaymentError::RailError("x402 facilitator settlement failed".to_owned()),
        })?;
        let payer = response.payer.as_deref().map(evm_address);
        let pending =
            !response.success && response.error_reason.as_deref() == Some(X402_SETTLEMENT_PENDING);
        let payer_bound = match payer {
            Some(payer) => payer.as_deref() == Some(identity.from.as_str()),
            None => pending,
        };
        let transaction = response.transaction.as_deref().and_then(bytes32);
        let settled = match transaction {
            Some(transaction) if response.network == identity.network && payer_bound => {
                Some(X402SettledAuthorization {
                    identity: identity.clone(),
                    transaction,
                    payment_payload_digest: canonical_digest(&body.payment_payload)?,
                    settlement_response_digest: canonical_digest(&response)?,
                })
            }
            _ => None,
        };
        match (response.success, pending, settled) {
            (true, _, Some(settled)) => Ok(settled),
            (false, true, Some(settled)) => Err(PaymentError::OutcomeUnknown {
                detail: "x402 settlement was broadcast but not confirmed".to_owned(),
                evidence: serde_json::json!({
                    "adapter": "x402",
                    "settlement": "pending",
                    "authorization_identity": identity.to_string(),
                    "x402": serde_json::to_value(settled.settlement_ref()).map_err(|error| {
                        PaymentError::RailError(format!(
                            "x402 settlement reference is invalid: {error}"
                        ))
                    })?,
                }),
            }),
            (true, _, None) | (false, true, None) => Err(PaymentError::RailError(
                "x402 settlement response binding is invalid".to_owned(),
            )),
            (false, false, _) => Err(PaymentError::RailError(
                "x402 facilitator did not confirm settlement".to_owned(),
            )),
        }
    }

    /// The settled authorization `authorization_id` names on this rail.
    fn bound_settlement(
        &self,
        authorization_id: &str,
    ) -> Result<X402SettledAuthorization, PaymentError> {
        let settled = X402SettledAuthorization::parse(authorization_id).ok_or_else(|| {
            PaymentError::RailError("x402 authorization identity is invalid".to_owned())
        })?;
        if settled.identity.network != self.rail.network.as_str()
            || settled.identity.asset != self.rail.asset
        {
            return Err(PaymentError::RailError(
                "x402 authorization identity is outside the configured rail".to_owned(),
            ));
        }
        Ok(settled)
    }
}

impl PaymentAdapter for X402PaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "x402"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let context = request.x402.as_ref().ok_or(X402Refusal::PaymentMissing)?;
        let (identity, valid_after) =
            self.check_payment(request, context, self.now_unix_secs()?)?;
        self.ensure_unspent(&identity)?;
        let body = X402FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: &context.payment_payload,
            payment_requirements: &context.payment_requirements,
        };
        self.verify(&body)?;
        self.spend(&identity, valid_after)?;
        let settled = self.settle(&body, &identity)?;
        let authorization_id = settled.to_string();
        if !payment_identifier_is_valid(&authorization_id) {
            return Err(PaymentError::RailError(
                "x402 authorization identifier is invalid".to_owned(),
            ));
        }
        Ok(PaymentAuthorization {
            authorization_id,
            state: PaymentAuthorizationState::PrepaidFinal,
            metadata: settled.authorization_metadata()?,
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "action": "capture",
                "reference": reference
            }),
        })
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable(
            "x402 final prepayment has no releasable hold".into(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable(
            "x402 remote refund is unsupported".into(),
        ))
    }

    /// x402 exposes no settlement status query, so every recovery query is
    /// `Unavailable` and the journal moves to `ReconcileFailed`. A presented
    /// identity is still checked against the configured rail.
    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        if !payment_identifier_is_valid(reference) {
            return Err(PaymentError::RailError(
                "x402 settlement-state reference is invalid".to_owned(),
            ));
        }
        if let Some(authorization_id) = authorization_id {
            self.bound_settlement(authorization_id)?;
        }
        Err(PaymentError::Unavailable(
            "x402 has no settlement status query".to_owned(),
        ))
    }

    /// The settlement reference is part of the journaled authorization
    /// identifier, so replay rebuilds the original authorization metadata.
    fn replayed_authorization_metadata(
        &self,
        authorization_id: &str,
    ) -> Result<serde_json::Value, PaymentError> {
        self.bound_settlement(authorization_id)?
            .authorization_metadata()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct X402FacilitatorRequest<'a> {
    x402_version: u8,
    payment_payload: &'a X402PaymentPayload,
    payment_requirements: &'a X402PaymentRequirements,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402VerifyResponse {
    is_valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402SettleResponse {
    success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction: Option<String>,
    network: String,
}

/// EIP-3009 `transferWithAuthorization` requires `now > validAfter` and
/// `now < validBefore`, in Unix seconds.
fn check_window(now: u64, valid_after: u64, valid_before: u64) -> Result<(), X402Refusal> {
    if now <= valid_after {
        return Err(X402Refusal::NotYetValid { now, valid_after });
    }
    if now >= valid_before {
        return Err(X402Refusal::Expired { now, valid_before });
    }
    Ok(())
}

fn replay_store_unavailable() -> PaymentError {
    PaymentError::Unavailable("x402 replay store is unavailable".to_owned())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, PaymentError> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        PaymentError::RailError(format!("failed to canonicalize x402 binding: {error}"))
    })?;
    Ok(sha256(&canonical).to_hex())
}

fn hex_body(value: &str, len: usize) -> Option<String> {
    let body = value.strip_prefix("0x")?;
    (body.len() == len && body.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("0x{}", body.to_ascii_lowercase()))
}

/// Lowercase `0x` form of a 20-byte EVM address.
fn evm_address(value: &str) -> Option<String> {
    hex_body(value, 40)
}

/// A lowercase hex SHA-256 digest, as `canonical_digest` renders it.
fn sha256_hex(value: &str) -> Option<String> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| value.to_owned())
}

/// Lowercase `0x` form of a 32-byte word.
fn bytes32(value: &str) -> Option<String> {
    hex_body(value, 64)
}

fn decimal_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

fn signature_is_well_formed(signature: &str) -> bool {
    signature.strip_prefix("0x").is_some_and(|body| {
        !body.is_empty()
            && body.len() % 2 == 0
            && body.len() <= MAX_X402_SIGNATURE_HEX_BYTES
            && body.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

#[cfg(test)]
#[path = "x402/tests.rs"]
mod tests;
