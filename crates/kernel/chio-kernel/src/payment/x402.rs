//! x402 facilitator rail.
//!
//! Protocol: x402 v2 (`x402Version: 2`), `exact` scheme on EVM networks, where
//! the payer's `PaymentPayload` carries a signed EIP-3009
//! `transferWithAuthorization`. The adapter calls the facilitator's
//! `POST /verify` and then `POST /settle` with
//! `{ x402Version, paymentPayload, paymentRequirements }` before the tool runs,
//! so every authorization is a final prepayment.
//!
//! Rail truth for recovery comes from read-only JSON-RPC against the token
//! contract on an allowlisted testnet: `authorizationState(authorizer, nonce)`
//! plus the `AuthorizationUsed` and `AuthorizationCanceled` logs. The adapter
//! holds no keys and never broadcasts.

use std::fmt;
use std::time::Duration;

use chio_core::{canonical_json_bytes, sha256};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use super::{
    build_http_agent, payment_identifier_is_valid, post_json, PaymentAdapter, PaymentAuthorization,
    PaymentAuthorizationState, PaymentAuthorizeRequest, PaymentError, PaymentRailMode,
    PaymentResult, RailSettlementState, RailSettlementStatus, X402SettlementRef,
};

/// x402 protocol version this adapter speaks.
pub const X402_VERSION: u8 = 2;
/// The only x402 scheme this adapter accepts.
pub const X402_EXACT_SCHEME: &str = "exact";

const X402_VERIFY_PATH: &str = "/verify";
const X402_SETTLE_PATH: &str = "/settle";
const X402_AUTHORIZATION_ID_PREFIX: &str = "x402";
const MAX_X402_SIGNATURE_HEX_BYTES: usize = 4096;

/// `authorizationState(address,bytes32)` selector.
const AUTHORIZATION_STATE_SELECTOR: &str = "e94a0102";
/// `AuthorizationUsed(address,bytes32)` event topic.
const AUTHORIZATION_USED_TOPIC: &str =
    "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5";
/// `AuthorizationCanceled(address,bytes32)` event topic.
const AUTHORIZATION_CANCELED_TOPIC: &str =
    "0x1cdd46ff242716cdaa72d159d339a485b3438398348d68f09d7c8c0a59353d81";

/// CAIP-2 networks the x402 rail may settle on. On-chain value stays
/// rehearsal-only: Base Sepolia.
const X402_TESTNET_ALLOWLIST: &[&str] = &["eip155:84532"];

/// Why the x402 adapter refused a payment before any settlement was attempted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum X402Refusal {
    #[error("x402 network is not on the testnet allowlist")]
    NetworkNotAllowlisted,
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

/// Operator-configured rail the adapter settles to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402RailConfig {
    pub network: X402Network,
    /// EIP-3009 token contract, lowercase `0x` hex.
    pub asset: String,
    /// Currency code Chio charges in for this asset.
    pub currency: String,
    /// Payee address, lowercase `0x` hex.
    pub pay_to: String,
}

impl X402RailConfig {
    pub fn new(
        network: X402Network,
        asset: &str,
        currency: &str,
        pay_to: &str,
    ) -> Result<Self, X402Refusal> {
        let asset = evm_address(asset).ok_or(X402Refusal::RailMismatch)?;
        let pay_to = evm_address(pay_to).ok_or(X402Refusal::RailMismatch)?;
        if currency.trim().is_empty() || currency.trim() != currency {
            return Err(X402Refusal::RailMismatch);
        }
        Ok(Self {
            network,
            asset,
            currency: currency.to_owned(),
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

/// Rail coordinates that identify one x402 prepayment on chain. Rendered as
/// `x402/<caip2>/<asset>/<from>/<nonce>/<validBefore>` and used as the
/// authorization identifier, so recovery can query the rail from it alone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct X402AuthorizationIdentity {
    network: String,
    asset: String,
    from: String,
    nonce: String,
    valid_before: u64,
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

impl X402AuthorizationIdentity {
    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split('/');
        let (Some(prefix), Some(network), Some(asset), Some(from), Some(nonce), Some(before)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        if prefix != X402_AUTHORIZATION_ID_PREFIX || parts.next().is_some() {
            return None;
        }
        X402Network::allowlisted(network).ok()?;
        let identity = Self {
            network: network.to_owned(),
            asset: evm_address(asset)?,
            from: evm_address(from)?,
            nonce: bytes32(nonce)?,
            valid_before: decimal_u64(before)?,
        };
        (identity.to_string() == value).then_some(identity)
    }
}

/// x402 v2 facilitator adapter. Final prepayment only: there is no hold to
/// release and no remote refund.
#[derive(Clone)]
pub struct X402PaymentAdapter {
    facilitator_url: String,
    rpc_url: String,
    rail: X402RailConfig,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

impl fmt::Debug for X402PaymentAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X402PaymentAdapter")
            .field("facilitator_url", &self.facilitator_url)
            .field("rpc_url", &self.rpc_url)
            .field("rail", &self.rail)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

impl X402PaymentAdapter {
    #[must_use]
    pub fn new(
        facilitator_url: impl Into<String>,
        rpc_url: impl Into<String>,
        rail: X402RailConfig,
    ) -> Self {
        Self {
            facilitator_url: facilitator_url.into().trim_end_matches('/').to_string(),
            rpc_url: rpc_url.into(),
            rail,
            bearer_token: None,
            http: build_http_agent(Duration::from_secs(5)),
        }
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = build_http_agent(timeout);
        self
    }

    fn check_payment(
        &self,
        request: &PaymentAuthorizeRequest,
        context: &X402PaymentContext,
    ) -> Result<X402AuthorizationIdentity, X402Refusal> {
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
            || request.currency != self.rail.currency
            || requirements.max_timeout_seconds == 0
        {
            return Err(X402Refusal::RailMismatch);
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
        Ok(X402AuthorizationIdentity {
            network: self.rail.network.as_str().to_owned(),
            asset: self.rail.asset.clone(),
            from,
            nonce,
            valid_before,
        })
    }

    fn verify(&self, body: &X402FacilitatorRequest<'_>) -> Result<(), X402Refusal> {
        let response: X402VerifyResponse = post_json(
            &self.http,
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
    ) -> Result<X402SettlementRef, PaymentError> {
        let response: X402SettleResponse = post_json(
            &self.http,
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
        let response_digest = canonical_digest(&response)?;
        let payer_matches = response
            .payer
            .as_deref()
            .is_none_or(|payer| evm_address(payer).as_deref() == Some(identity.from.as_str()));
        let transaction = response.transaction.as_deref().and_then(bytes32);
        match (response.success, transaction) {
            (true, Some(transaction)) if response.network == identity.network && payer_matches => {
                Ok(X402SettlementRef {
                    x402_version: X402_VERSION,
                    scheme: X402_EXACT_SCHEME.to_owned(),
                    network: identity.network.clone(),
                    transaction,
                    payer: identity.from.clone(),
                    payment_payload_digest: canonical_digest(&body.payment_payload)?,
                    settlement_response_digest: response_digest,
                })
            }
            (true, _) => Err(PaymentError::RailError(
                "x402 settlement response binding is invalid".to_owned(),
            )),
            (false, _) => Err(PaymentError::RailError(
                "x402 facilitator did not confirm settlement".to_owned(),
            )),
        }
    }

    fn rail_state(
        &self,
        identity: &X402AuthorizationIdentity,
        authorization_id: &str,
    ) -> Result<RailSettlementState, PaymentError> {
        let rpc = EvmRpc {
            http: &self.http,
            url: &self.rpc_url,
        };
        if rpc.authorization_used(identity)? {
            if let Some(transaction) = rpc.authorization_log(identity, AUTHORIZATION_USED_TOPIC)? {
                return Ok(RailSettlementState::Settled {
                    authorization_id: authorization_id.to_owned(),
                    result: PaymentResult {
                        transaction_id: authorization_id.to_owned(),
                        settlement_status: RailSettlementStatus::Settled,
                        metadata: serde_json::json!({
                            "adapter": "x402",
                            "network": identity.network,
                            "transaction": transaction,
                        }),
                    },
                });
            }
            if rpc
                .authorization_log(identity, AUTHORIZATION_CANCELED_TOPIC)?
                .is_some()
            {
                return Ok(RailSettlementState::NoAuthorization);
            }
            return Err(PaymentError::Unavailable(
                "x402 authorization is consumed but its rail event was not found".to_owned(),
            ));
        }
        if rpc.latest_block_timestamp()? >= identity.valid_before {
            return Ok(RailSettlementState::NoAuthorization);
        }
        Err(PaymentError::Unavailable(
            "x402 authorization is unused and still valid".to_owned(),
        ))
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
        let identity = self.check_payment(request, context)?;
        let body = X402FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: &context.payment_payload,
            payment_requirements: &context.payment_requirements,
        };
        self.verify(&body)?;
        let settlement = self.settle(&body, &identity)?;
        let authorization_id = identity.to_string();
        if !payment_identifier_is_valid(&authorization_id) {
            return Err(PaymentError::RailError(
                "x402 authorization identifier is invalid".to_owned(),
            ));
        }
        let x402 = serde_json::to_value(&settlement).map_err(|error| {
            PaymentError::RailError(format!("x402 settlement reference is invalid: {error}"))
        })?;
        Ok(PaymentAuthorization {
            authorization_id,
            state: PaymentAuthorizationState::PrepaidFinal,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "x402": x402,
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

    /// Recovery asks with the durable reference alone, which carries no rail
    /// coordinates, so that form answers `Unavailable` and the journal moves
    /// to `ReconcileFailed`.
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
        let Some(authorization_id) = authorization_id else {
            return Err(PaymentError::Unavailable(
                "x402 settlement state requires the authorization identity".to_owned(),
            ));
        };
        let identity = X402AuthorizationIdentity::parse(authorization_id).ok_or_else(|| {
            PaymentError::RailError("x402 authorization identity is invalid".to_owned())
        })?;
        if identity.network != self.rail.network.as_str() || identity.asset != self.rail.asset {
            return Err(PaymentError::RailError(
                "x402 authorization identity is outside the configured rail".to_owned(),
            ));
        }
        self.rail_state(&identity, authorization_id)
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

/// Read-only JSON-RPC client. Every failure is `Unavailable`: a status query
/// has no effect, so a failed read never proves anything about the rail.
struct EvmRpc<'a> {
    http: &'a ureq::Agent,
    url: &'a str,
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    id: u64,
    result: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvmLog {
    address: String,
    topics: Vec<String>,
    transaction_hash: String,
    #[serde(default)]
    removed: bool,
}

#[derive(Deserialize)]
struct EvmBlock {
    timestamp: String,
}

impl EvmRpc<'_> {
    fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, PaymentError> {
        let unavailable = || PaymentError::Unavailable("x402 rail RPC is unavailable".to_owned());
        let parsed = Url::parse(self.url).map_err(|_| unavailable())?;
        let base = parsed.origin().ascii_serialization();
        let response: JsonRpcResponse<T> = post_json(
            self.http,
            &base,
            None,
            parsed.path(),
            &JsonRpcRequest {
                jsonrpc: "2.0",
                id: 1,
                method,
                params,
            },
        )
        .map_err(|_| unavailable())?;
        if response.id != 1 {
            return Err(unavailable());
        }
        response.result.ok_or_else(unavailable)
    }

    fn authorization_used(
        &self,
        identity: &X402AuthorizationIdentity,
    ) -> Result<bool, PaymentError> {
        let data = format!(
            "0x{AUTHORIZATION_STATE_SELECTOR}{}{}",
            address_word(&identity.from),
            hex_digits(&identity.nonce)
        );
        let result: String = self.call(
            "eth_call",
            serde_json::json!([{ "to": identity.asset, "data": data }, "latest"]),
        )?;
        let word = bytes32(&result).ok_or_else(|| {
            PaymentError::Unavailable("x402 rail RPC returned an invalid state".to_owned())
        })?;
        let (head, last) = hex_digits(&word).split_at(63);
        match (head.bytes().all(|byte| byte == b'0'), last) {
            (true, "0") => Ok(false),
            (true, "1") => Ok(true),
            _ => Err(PaymentError::Unavailable(
                "x402 rail RPC returned an invalid state".to_owned(),
            )),
        }
    }

    fn authorization_log(
        &self,
        identity: &X402AuthorizationIdentity,
        topic: &str,
    ) -> Result<Option<String>, PaymentError> {
        let authorizer_topic = format!("0x{}", address_word(&identity.from));
        let logs: Vec<EvmLog> = self.call(
            "eth_getLogs",
            serde_json::json!([{
                "address": identity.asset,
                "topics": [topic, authorizer_topic, identity.nonce],
                "fromBlock": "earliest",
                "toBlock": "latest",
            }]),
        )?;
        let mut matching = logs.into_iter().filter(|log| {
            !log.removed
                && evm_address(&log.address).as_deref() == Some(identity.asset.as_str())
                && matches!(
                    log.topics.as_slice(),
                    [event, authorizer, nonce]
                        if event.eq_ignore_ascii_case(topic)
                            && authorizer.eq_ignore_ascii_case(&authorizer_topic)
                            && nonce.eq_ignore_ascii_case(&identity.nonce)
                )
        });
        let Some(first) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(PaymentError::Unavailable(
                "x402 rail RPC returned duplicate authorization events".to_owned(),
            ));
        }
        bytes32(&first.transaction_hash).map(Some).ok_or_else(|| {
            PaymentError::Unavailable("x402 rail RPC returned an invalid transaction".to_owned())
        })
    }

    fn latest_block_timestamp(&self) -> Result<u64, PaymentError> {
        let block: EvmBlock =
            self.call("eth_getBlockByNumber", serde_json::json!(["latest", false]))?;
        quantity_u64(&block.timestamp).ok_or_else(|| {
            PaymentError::Unavailable("x402 rail RPC returned an invalid block".to_owned())
        })
    }
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

/// Lowercase `0x` form of a 32-byte word.
fn bytes32(value: &str) -> Option<String> {
    hex_body(value, 64)
}

fn address_word(address: &str) -> String {
    format!("{:0>64}", hex_digits(address))
}

/// Digits of a validated `0x` hex string.
fn hex_digits(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
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

fn quantity_u64(value: &str) -> Option<u64> {
    let digits = value.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 16 || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
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
