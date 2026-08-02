use std::time::Duration;

use chio_core::{capability::scope::MonetaryAmount, receipt::economics::SettlementStatus};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod sim;
pub use sim::SimPaymentAdapter;

/// Result of a payment authorization or settlement hold.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentAuthorization {
    /// Payment rail's authorization or hold identifier.
    pub authorization_id: String,
    /// Whether the rail already considers the funds fully settled.
    pub settled: bool,
    /// Rail-specific metadata such as idempotency keys, quote IDs, or expiry.
    pub metadata: serde_json::Value,
}

/// Single-use credential disposition after payment authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCredentialDisposition {
    NonePresent,
    RetainedAfterAuthorization,
    RetentionOutcomeUnknown,
}

/// Exact terminal rail action used to unwind a pre-dispatch authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreDispatchPaymentUnwindStatus {
    Released,
    Refunded,
}

/// Typed evidence embedded in a signed terminal receipt after a clean unwind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreDispatchPaymentUnwindEvidence {
    pub authorization_id: String,
    pub transaction_id: String,
    pub settlement_status: PreDispatchPaymentUnwindStatus,
    pub credential_disposition: PaymentCredentialDisposition,
}

/// Result of a capture, settlement, release, or refund operation.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentResult {
    /// Stable rail reference for the resulting financial operation.
    pub transaction_id: String,
    /// Richer rail-side settlement state, mapped onto the canonical receipt enum.
    pub settlement_status: RailSettlementStatus,
    /// Rail-specific metadata such as confirmations or idempotency keys.
    pub metadata: serde_json::Value,
}

/// Richer settlement states surfaced by payment rails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailSettlementStatus {
    Authorized,
    Captured,
    Settled,
    Pending,
    Failed,
    Released,
    Refunded,
}

impl RailSettlementStatus {
    /// Map rail-specific settlement states onto the receipt-side canonical enum.
    #[must_use]
    pub const fn to_receipt_status(self) -> SettlementStatus {
        match self {
            Self::Authorized | Self::Captured | Self::Pending => SettlementStatus::Pending,
            Self::Settled | Self::Released | Self::Refunded => SettlementStatus::Settled,
            Self::Failed => SettlementStatus::Failed,
        }
    }
}

/// Canonical settlement fields as they appear on signed financial receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSettlement {
    pub payment_reference: Option<String>,
    pub settlement_status: SettlementStatus,
}

/// Governed request details forwarded to payment rails when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedPaymentContext {
    pub intent_id: String,
    pub intent_hash: String,
    pub purpose: String,
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
}

/// Commerce approval details forwarded to seller-scoped payment rails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommercePaymentContext {
    pub seller: String,
    pub settlement_destination_ref: String,
    pub payee_binding_digest: String,
    pub pre_action_authority_digest: String,
    pub shared_payment_token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
}

/// Canonical authorization request forwarded to a payment rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAuthorizeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_binding_hash: Option<String>,
    pub amount_units: u64,
    pub currency: String,
    pub payer: String,
    pub payee: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed: Option<GovernedPaymentContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<CommercePaymentContext>,
}

/// Operation-bound capture details passed to an idempotent payment rail.
#[derive(Debug, Clone, Copy)]
pub struct OperationPaymentCaptureRequest<'a> {
    pub operation_id: &'a str,
    pub request_binding_hash: &'a str,
    pub authorization_id: &'a str,
    pub amount_units: u64,
    pub currency: &'a str,
    pub reference: &'a str,
}

/// Operation-bound refund details passed to an idempotent payment rail.
#[derive(Debug, Clone, Copy)]
pub struct OperationPaymentRefundRequest<'a> {
    pub operation_id: &'a str,
    pub request_binding_hash: &'a str,
    pub transaction_id: &'a str,
    pub amount_units: u64,
    pub currency: &'a str,
    pub reference: &'a str,
}

impl ReceiptSettlement {
    #[must_use]
    pub const fn not_applicable() -> Self {
        Self {
            payment_reference: None,
            settlement_status: SettlementStatus::NotApplicable,
        }
    }

    #[must_use]
    pub const fn settled() -> Self {
        Self {
            payment_reference: None,
            settlement_status: SettlementStatus::Settled,
        }
    }

    #[must_use]
    pub const fn failed() -> Self {
        Self {
            payment_reference: None,
            settlement_status: SettlementStatus::Failed,
        }
    }

    #[must_use]
    pub fn from_authorization(authorization: &PaymentAuthorization) -> Self {
        Self {
            payment_reference: Some(authorization.authorization_id.clone()),
            settlement_status: if authorization.settled {
                SettlementStatus::Settled
            } else {
                SettlementStatus::Pending
            },
        }
    }

    #[must_use]
    pub fn from_payment_result(result: &PaymentResult) -> Self {
        Self {
            payment_reference: Some(result.transaction_id.clone()),
            settlement_status: result.settlement_status.to_receipt_status(),
        }
    }

    #[must_use]
    pub fn into_receipt_parts(self) -> (Option<String>, SettlementStatus) {
        (self.payment_reference, self.settlement_status)
    }
}

/// Side-effect-free snapshot of a rail's view of a prior authorization,
/// returned by [`PaymentAdapter::settlement_state`]. Distinct from
/// [`PaymentResult`] because the crash window this query answers spans a
/// case `PaymentResult` cannot express on its own: a hold that exists but
/// has not settled. Carrying that distinction explicitly lets
/// reconciliation release a proven hold-only authorization while never
/// releasing, and thereby erasing the only record of, funds the rail
/// already moved.
#[derive(Debug, Clone, PartialEq)]
pub enum RailSettlementState {
    /// The rail has no hold or settlement for this reference: `authorize`
    /// never took effect. Reconciliation reverses the local budget hold and
    /// closes the journal; funds never moved.
    NoAuthorization,
    /// A hold exists but no funds have moved. Carries the rail-assigned
    /// `authorization_id` so reconciliation can release it.
    Held {
        /// Rail-assigned identifier for the open, unsettled hold.
        authorization_id: String,
    },
    /// Funds already moved on the rail. Carries the rail-assigned
    /// `authorization_id` and the settled result so reconciliation records
    /// the id and emits a durable receipt for the already-moved amount
    /// instead of releasing it.
    Settled {
        /// Rail-assigned identifier for the settled authorization.
        authorization_id: String,
        /// The rail's settlement result for the moved funds.
        result: PaymentResult,
    },
}

/// Trait for executing payments against an external rail.
pub trait PaymentAdapter: Send + Sync {
    /// Stable identifier of the rail this adapter drives, recorded on
    /// monetary dispatch intents so an operator can reconcile a monetary
    /// orphan against the correct rail without guessing.
    fn rail_id(&self) -> &str {
        "payment"
    }

    /// Whether this adapter can authoritatively look up an operation-owned
    /// authorization after the authorize acknowledgement is lost.
    ///
    /// Operation-owned ordinary admission rejects adapters that return
    /// `false` at activation time. Implementations must only return `true`
    /// when [`Self::lookup_authorization_for_operation`] is linearizable with
    /// [`Self::authorize_for_operation`] for the exact operation and request
    /// binding.
    fn supports_operation_authorization_recovery(&self) -> bool {
        false
    }

    /// Whether every rail mutation and settlement-state query has an exact
    /// operation-owned implementation.
    ///
    /// Operation-owned ordinary admission rejects adapters that return
    /// `false` at activation time. Implementations must only return `true`
    /// when capture, release, refund, and settlement-state operations preserve
    /// the operation id and request binding and are idempotent on exact retry.
    fn supports_operation_payment_mutations(&self) -> bool {
        false
    }

    /// Authorize or prepay up to `amount_units` before the tool executes.
    ///
    /// Contract: implementations MUST be idempotent keyed on
    /// `request.reference` (the durable request id the kernel records
    /// before the call). A repeated authorize with the same reference
    /// returns the same authorization and places AT MOST ONE rail-side
    /// hold, so crash recovery can re-drive the call without stacking
    /// holds.
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError>;

    /// Finalize payment for the actual cost after tool execution.
    ///
    /// Contract: implementations MUST be idempotent keyed on
    /// `(authorization_id, reference)`. A repeated call with the same key
    /// returns an equivalent [`PaymentResult`] and moves money AT MOST
    /// ONCE; boot reconciliation replays a committed capture relying on
    /// this.
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Release an unused authorization hold.
    ///
    /// Contract: implementations MUST be idempotent keyed on
    /// `(authorization_id, reference)`, releasing the hold AT MOST ONCE.
    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Refund a previously executed payment.
    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Authorize an operation-owned payment.
    ///
    /// Implementations must treat `operation_id` as an idempotency and lookup
    /// key. An exact retry must return the original authorization without
    /// creating a second rail-side hold, while reuse with a different request
    /// binding must fail closed. The default deliberately rejects because the
    /// legacy `authorize` contract provides neither guarantee.
    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        if request.operation_id.as_deref() != Some(operation_id)
            || request.request_binding_hash.as_deref() != Some(request_binding_hash)
        {
            return Err(PaymentError::RailError(
                "payment authorization request does not match its admission operation".to_string(),
            ));
        }
        Err(PaymentError::OperationIdempotencyUnsupported("authorize"))
    }

    /// Query the authoritative authorization result for an operation.
    ///
    /// The lookup must be linearizable with `authorize_for_operation`: `None`
    /// proves that no authorization exists for the exact operation and request
    /// binding at the observed point, while `Some` returns the original result.
    /// This is the recovery boundary after an authorization acknowledgement is
    /// lost. The default rejects because a legacy adapter cannot prove absence.
    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        Err(PaymentError::OperationIdempotencyUnsupported(
            "authorization lookup",
        ))
    }

    /// Capture an operation-owned payment authorization. Exact retries must
    /// return the original result without a second rail-side capture.
    fn capture_for_operation(
        &self,
        request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let OperationPaymentCaptureRequest {
            operation_id,
            request_binding_hash,
            authorization_id,
            amount_units,
            currency,
            reference,
        } = request;
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let _ = (authorization_id, amount_units, currency, reference);
        Err(PaymentError::OperationIdempotencyUnsupported("capture"))
    }

    /// Void an unused operation-owned payment authorization. Exact retries
    /// must return the original result without a second rail-side release.
    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let _ = (authorization_id, reference);
        Err(PaymentError::OperationIdempotencyUnsupported("release"))
    }

    /// Refund an operation-owned payment that was already settled. Exact
    /// retries must return the original result without a second rail-side
    /// refund.
    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let OperationPaymentRefundRequest {
            operation_id,
            request_binding_hash,
            transaction_id,
            amount_units,
            currency,
            reference,
        } = request;
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let _ = (transaction_id, amount_units, currency, reference);
        Err(PaymentError::OperationIdempotencyUnsupported("refund"))
    }

    /// Query settlement state for an operation-owned authorization. The
    /// operation identity and request binding are part of the lookup key, so
    /// recovery cannot query or release a rail hold under a rebound journal.
    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let _ = (reference, authorization_id);
        Err(PaymentError::OperationIdempotencyUnsupported(
            "settlement state lookup",
        ))
    }

    /// Query the current rail-side settlement state for a prior
    /// authorization WITHOUT moving funds. Idempotent and side-effect-free.
    ///
    /// Keyed on `reference` (the durable request id recorded before
    /// authorize) so it stays answerable in the crash window where no
    /// authorization id is durable yet; `authorization_id` is an optional
    /// refinement passed once known. The returned `RailSettlementState`
    /// distinguishes a live, unsettled hold from funds that already moved,
    /// so reconciliation releases only a proven hold and never mistakes an
    /// already-settled charge for one. Defaulted to `Unavailable` so an
    /// adapter that cannot answer forces a fail-closed operator incident
    /// during reconciliation rather than a silent close.
    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let _ = (reference, authorization_id);
        Err(PaymentError::Unavailable(
            "this adapter does not expose settlement_state queries".to_string(),
        ))
    }
}

fn validate_payment_operation_binding(
    operation_id: &str,
    request_binding_hash: &str,
) -> Result<(), PaymentError> {
    if operation_id.is_empty()
        || operation_id.len() > 512
        || operation_id.bytes().any(|byte| byte == 0)
    {
        return Err(PaymentError::RailError(
            "payment operation_id is empty, oversized, or contains NUL".to_string(),
        ));
    }
    if request_binding_hash.len() != 64
        || !request_binding_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PaymentError::RailError(
            "payment request_binding_hash must be lowercase SHA-256 hex".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("payment declined: {0}")]
    Declined(String),

    #[error("insufficient funds")]
    InsufficientFunds,

    #[error("payment rail unavailable: {0}")]
    Unavailable(String),

    #[error("payment adapter does not support operation-owned idempotency for {0}")]
    OperationIdempotencyUnsupported(&'static str),

    #[error("payment rail error: {0}")]
    RailError(String),
}

/// Durable money-path journal state. One row per priced request, written
/// before the rail is touched and advanced around every rail call, so a
/// crash in any window leaves a recoverable record instead of moved funds
/// with no trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentJournalState {
    /// Row written with the budget hold, before the rail authorize call.
    HoldPlaced,
    /// The rail authorize returned; the authorization id is recorded.
    Authorized,
    /// About to call capture or release; the rail may move money next.
    Settling,
    /// Capture returned settled or release returned released.
    Settled,
    /// Receipt persisted; terminal success.
    Closed,
    /// Boot reconciliation could not settle or determine the outcome;
    /// operator incident.
    ReconcileFailed,
}

/// Terminal action committed before entering [`PaymentJournalState::Settling`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSettleAction {
    /// Capture the recorded amount from the hold.
    Capture,
    /// Release the whole hold without capturing.
    Release,
    /// Refund a settled authorization using its recorded transaction id.
    Refund,
}

/// The committed settle decision, stamped atomically with the advance to
/// `Settling` so reconciliation replays the exact operation rather than
/// guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentSettleIntent {
    /// The rail call recovery must replay for an in-flight settle.
    pub action: PaymentSettleAction,
    /// Exact amount for `Capture` or `Refund`; `None` for `Release`.
    pub amount_units: Option<u64>,
}

/// One durable payment-journal row, keyed by the request id the kernel also
/// uses as the rail idempotency reference.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentJournalRecord {
    pub request_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    /// Durable operation identity for operation-owned budget and rail
    /// mutations. Legacy journal rows omit this binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_operation: Option<crate::budget_store::BudgetAdmissionOperationBinding>,
    /// Budget authority lease that created the hold. Recovery replays this
    /// exact fence when a durable hold carries authority metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<crate::budget_store::BudgetEventAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    pub rail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Budget exposure reserved by the associated hold. This can be zero for
    /// a no-ceiling prepaid rail authorization whose rail amount is nonzero.
    #[serde(default)]
    pub budget_exposure_units: u64,
    pub amount_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_action: Option<PaymentSettleAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_amount_units: Option<u64>,
    pub currency: String,
    pub state: PaymentJournalState,
    pub created_at_unix_ms: u64,
    /// Tenant that owns this request, resolved exactly as the terminal
    /// receipt resolves it (request-scoped entry first, thread-local scope
    /// otherwise). `None` in single-tenant deployments. Threaded onto a
    /// reconciliation receipt so a recovered charge is never dropped from
    /// the owning tenant's receipt view (see [`crate::kernel::ChioKernel`]
    /// reconciliation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// Thin prepaid HTTP payment bridge for x402-style per-request settlement.
///
/// The adapter performs a remote authorization plus a side-effect-free exact
/// operation lookup for acknowledgement-loss recovery. Operation responses
/// must echo the exact operation id and request binding. Later
/// capture/release/refund actions are prepaid bookkeeping.
#[derive(Debug, Clone)]
pub struct X402PaymentAdapter {
    base_url: String,
    authorize_path: String,
    authorize_lookup_path: String,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

/// Thin shared-payment-token payment bridge for ACP-style commerce approvals.
///
/// This adapter performs a remote authorization plus a side-effect-free exact
/// operation lookup for acknowledgement-loss recovery. Operation responses
/// must echo the exact operation id and request binding. The kernel then
/// reconciles the local hold as capture/release/refund bookkeeping.
#[derive(Debug, Clone)]
pub struct AcpPaymentAdapter {
    base_url: String,
    authorize_path: String,
    authorize_lookup_path: String,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

impl X402PaymentAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            authorize_path: "/authorize".to_string(),
            authorize_lookup_path: "/authorize/lookup".to_string(),
            bearer_token: None,
            http: build_http_agent(Duration::from_secs(5)),
        }
    }

    #[must_use]
    pub fn with_authorize_path(mut self, path: impl Into<String>) -> Self {
        self.authorize_path = normalize_http_path(&path.into());
        self
    }

    /// Configure the rail endpoint that performs a side-effect-free lookup
    /// by exact `operationId` and `requestBindingHash`. A successful JSON
    /// `null` response proves absence; an object returns the original result
    /// and must echo both binding fields. Every non-success response fails
    /// closed.
    #[must_use]
    pub fn with_authorize_lookup_path(mut self, path: impl Into<String>) -> Self {
        self.authorize_lookup_path = normalize_http_path(&path.into());
        self
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
}

impl AcpPaymentAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            authorize_path: "/authorize".to_string(),
            authorize_lookup_path: "/authorize/lookup".to_string(),
            bearer_token: None,
            http: build_http_agent(Duration::from_secs(5)),
        }
    }

    #[must_use]
    pub fn with_authorize_path(mut self, path: impl Into<String>) -> Self {
        self.authorize_path = normalize_http_path(&path.into());
        self
    }

    /// Configure the rail endpoint that performs a side-effect-free lookup
    /// by exact `operationId` and `requestBindingHash`. A successful JSON
    /// `null` response proves absence; an object returns the original result
    /// and must echo both binding fields. Every non-success response fails
    /// closed.
    #[must_use]
    pub fn with_authorize_lookup_path(mut self, path: impl Into<String>) -> Self {
        self.authorize_lookup_path = normalize_http_path(&path.into());
        self
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
}

impl PaymentAdapter for X402PaymentAdapter {
    fn rail_id(&self) -> &str {
        "x402"
    }

    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        validate_operation_authorize_request(operation_id, request_binding_hash, request)?;
        let response: X402AuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            &OperationAuthorizationRequest::new(operation_id, request_binding_hash, request),
        )?;
        validate_operation_authorization_echo(
            response.operation_id.as_deref(),
            response.request_binding_hash.as_deref(),
            operation_id,
            request_binding_hash,
        )?;
        bind_operation_authorization(
            x402_authorization_from_response(response),
            operation_id,
            request_binding_hash,
        )
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let response: Option<X402AuthorizeResponse> = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_lookup_path,
            &OperationAuthorizationLookupRequest {
                operation_id,
                request_binding_hash,
            },
        )?;
        response
            .map(|response| {
                validate_operation_authorization_echo(
                    response.operation_id.as_deref(),
                    response.request_binding_hash.as_deref(),
                    operation_id,
                    request_binding_hash,
                )?;
                bind_operation_authorization(
                    x402_authorization_from_response(response),
                    operation_id,
                    request_binding_hash,
                )
            })
            .transpose()
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        operation_settlement_state_from_lookup(
            self.lookup_authorization_for_operation(operation_id, request_binding_hash)?,
            operation_id,
            request_binding_hash,
            authorization_id,
            "x402",
            "prepaid",
            reference,
        )
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        // Prepaid rail: funds move at authorize and capture is a local
        // no-op, so a durable authorization id is proof authorize returned
        // and the truthful answer is Settled - reconciliation must never
        // release a hold discovered through it. With only the reference
        // (the HoldPlaced crash window) authorize may never have reached
        // the rail, and this thin bridge has no reference-keyed rail
        // query: answering Settled would fabricate a reconciliation
        // receipt for money that may never have moved, so fail closed to
        // an operator incident instead.
        let Some(authorization_id) = authorization_id else {
            return Err(PaymentError::Unavailable(format!(
                "x402 adapter cannot confirm settlement for reference `{reference}` without \
                 a durable authorization id"
            )));
        };
        let authorization_id = authorization_id.to_string();
        Ok(RailSettlementState::Settled {
            authorization_id: authorization_id.clone(),
            result: PaymentResult {
                transaction_id: authorization_id,
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({
                    "adapter": "x402",
                    "mode": "prepaid",
                    "action": "settlement_state",
                    "reference": reference
                }),
            },
        })
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let response: X402AuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            request,
        )?;
        Ok(x402_authorization_from_response(response))
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
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "action": "release",
                "reference": reference
            }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "action": "refund",
                "amount_units": amount_units,
                "currency": currency,
                "reference": reference
            }),
        })
    }
}

impl PaymentAdapter for AcpPaymentAdapter {
    fn rail_id(&self) -> &str {
        "acp"
    }

    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        validate_operation_authorize_request(operation_id, request_binding_hash, request)?;
        let response: AcpAuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            &OperationAuthorizationRequest::new(operation_id, request_binding_hash, request),
        )?;
        validate_operation_authorization_echo(
            response.operation_id.as_deref(),
            response.request_binding_hash.as_deref(),
            operation_id,
            request_binding_hash,
        )?;
        bind_operation_authorization(
            acp_authorization_from_response(response),
            operation_id,
            request_binding_hash,
        )
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        validate_payment_operation_binding(operation_id, request_binding_hash)?;
        let response: Option<AcpAuthorizeResponse> = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_lookup_path,
            &OperationAuthorizationLookupRequest {
                operation_id,
                request_binding_hash,
            },
        )?;
        response
            .map(|response| {
                validate_operation_authorization_echo(
                    response.operation_id.as_deref(),
                    response.request_binding_hash.as_deref(),
                    operation_id,
                    request_binding_hash,
                )?;
                bind_operation_authorization(
                    acp_authorization_from_response(response),
                    operation_id,
                    request_binding_hash,
                )
            })
            .transpose()
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        operation_settlement_state_from_lookup(
            self.lookup_authorization_for_operation(operation_id, request_binding_hash)?,
            operation_id,
            request_binding_hash,
            authorization_id,
            "acp",
            "shared_payment_token_hold",
            reference,
        )
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        // The shared-payment-token hold settles at authorize time and the
        // local capture/release are no-ops, so a durable authorization id
        // is proof authorize returned and the truthful answer is Settled -
        // reconciliation must never release a hold discovered through it.
        // With only the reference (the HoldPlaced crash window) authorize
        // may never have reached the rail, and this thin bridge has no
        // reference-keyed rail query: answering Settled would fabricate a
        // reconciliation receipt for money that may never have moved, so
        // fail closed to an operator incident instead.
        let Some(authorization_id) = authorization_id else {
            return Err(PaymentError::Unavailable(format!(
                "acp adapter cannot confirm settlement for reference `{reference}` without \
                 a durable authorization id"
            )));
        };
        let authorization_id = authorization_id.to_string();
        Ok(RailSettlementState::Settled {
            authorization_id: authorization_id.clone(),
            result: PaymentResult {
                transaction_id: authorization_id,
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({
                    "adapter": "acp",
                    "mode": "shared_payment_token_hold",
                    "action": "settlement_state",
                    "reference": reference
                }),
            },
        })
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let response: AcpAuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            request,
        )?;
        Ok(acp_authorization_from_response(response))
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold",
                "action": "capture",
                "amount_units": amount_units,
                "currency": currency,
                "reference": reference
            }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold",
                "action": "release",
                "reference": reference
            }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold",
                "action": "refund",
                "amount_units": amount_units,
                "currency": currency,
                "reference": reference
            }),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402AuthorizeResponse {
    #[serde(
        alias = "authorization_id",
        alias = "transaction_id",
        alias = "transactionId"
    )]
    authorization_id: String,
    #[serde(default, alias = "operation_id")]
    operation_id: Option<String>,
    #[serde(default, alias = "request_binding_hash")]
    request_binding_hash: Option<String>,
    #[serde(default = "default_true")]
    settled: bool,
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcpAuthorizeResponse {
    #[serde(
        alias = "authorization_id",
        alias = "token_id",
        alias = "tokenId",
        alias = "authorizationId"
    )]
    authorization_id: String,
    #[serde(default, alias = "operation_id")]
    operation_id: Option<String>,
    #[serde(default, alias = "request_binding_hash")]
    request_binding_hash: Option<String>,
    #[serde(default)]
    settled: bool,
    #[serde(default)]
    metadata: serde_json::Value,
}

include!("payment/operation_adapter_support.inc");

fn x402_authorization_from_response(response: X402AuthorizeResponse) -> PaymentAuthorization {
    let metadata = if response.metadata.is_null() {
        serde_json::json!({})
    } else {
        response.metadata
    };
    PaymentAuthorization {
        authorization_id: response.authorization_id,
        settled: response.settled,
        metadata: merge_json_values(
            Some(metadata),
            Some(serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid"
            })),
        )
        .unwrap_or_else(|| serde_json::json!({ "adapter": "x402", "mode": "prepaid" })),
    }
}

fn acp_authorization_from_response(response: AcpAuthorizeResponse) -> PaymentAuthorization {
    let metadata = if response.metadata.is_null() {
        serde_json::json!({})
    } else {
        response.metadata
    };
    PaymentAuthorization {
        authorization_id: response.authorization_id,
        settled: response.settled,
        metadata: merge_json_values(
            Some(metadata),
            Some(serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold"
            })),
        )
        .unwrap_or_else(|| {
            serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold"
            })
        }),
    }
}

fn validate_operation_authorize_request(
    operation_id: &str,
    request_binding_hash: &str,
    request: &PaymentAuthorizeRequest,
) -> Result<(), PaymentError> {
    validate_payment_operation_binding(operation_id, request_binding_hash)?;
    if request.operation_id.as_deref() != Some(operation_id)
        || request.request_binding_hash.as_deref() != Some(request_binding_hash)
    {
        return Err(PaymentError::RailError(
            "payment authorization request does not match its admission operation".to_string(),
        ));
    }
    Ok(())
}

fn bind_operation_authorization(
    mut authorization: PaymentAuthorization,
    operation_id: &str,
    request_binding_hash: &str,
) -> Result<PaymentAuthorization, PaymentError> {
    if authorization.authorization_id.is_empty()
        || authorization.authorization_id.bytes().any(|byte| byte == 0)
    {
        return Err(PaymentError::RailError(
            "operation-owned payment authorization returned an invalid identifier".to_string(),
        ));
    }
    stamp_operation_metadata(
        &mut authorization.metadata,
        operation_id,
        request_binding_hash,
    )?;
    Ok(authorization)
}

fn bind_operation_payment_result(
    mut result: PaymentResult,
    operation_id: &str,
    request_binding_hash: &str,
) -> Result<PaymentResult, PaymentError> {
    if result.transaction_id.is_empty() || result.transaction_id.bytes().any(|byte| byte == 0) {
        return Err(PaymentError::RailError(
            "operation-owned payment mutation returned an invalid transaction identifier"
                .to_string(),
        ));
    }
    stamp_operation_metadata(&mut result.metadata, operation_id, request_binding_hash)?;
    Ok(result)
}

fn operation_settlement_state_from_lookup(
    authorization: Option<PaymentAuthorization>,
    operation_id: &str,
    request_binding_hash: &str,
    expected_authorization_id: Option<&str>,
    adapter: &str,
    mode: &str,
    reference: &str,
) -> Result<RailSettlementState, PaymentError> {
    let Some(authorization) = authorization else {
        return Ok(RailSettlementState::NoAuthorization);
    };
    if expected_authorization_id
        .is_some_and(|expected| expected != authorization.authorization_id.as_str())
    {
        return Err(PaymentError::RailError(
            "operation settlement lookup returned a different authorization".to_string(),
        ));
    }
    if !authorization.settled {
        return Ok(RailSettlementState::Held {
            authorization_id: authorization.authorization_id,
        });
    }
    let authorization_id = authorization.authorization_id;
    let metadata = merge_json_values(
        Some(authorization.metadata),
        Some(serde_json::json!({
            "adapter": adapter,
            "mode": mode,
            "action": "settlement_state",
            "reference": reference
        })),
    )
    .unwrap_or_else(|| serde_json::json!({}));
    Ok(RailSettlementState::Settled {
        authorization_id: authorization_id.clone(),
        result: bind_operation_payment_result(
            PaymentResult {
                transaction_id: authorization_id,
                settlement_status: RailSettlementStatus::Settled,
                metadata,
            },
            operation_id,
            request_binding_hash,
        )?,
    })
}

fn stamp_operation_metadata(
    metadata: &mut serde_json::Value,
    operation_id: &str,
    request_binding_hash: &str,
) -> Result<(), PaymentError> {
    validate_payment_operation_binding(operation_id, request_binding_hash)?;
    if metadata.is_null() {
        *metadata = serde_json::json!({});
    }
    let object = metadata.as_object_mut().ok_or_else(|| {
        PaymentError::RailError(
            "operation-owned payment metadata must be a JSON object".to_string(),
        )
    })?;
    validate_existing_operation_metadata(object, &["operationId", "operation_id"], operation_id)?;
    validate_existing_operation_metadata(
        object,
        &["requestBindingHash", "request_binding_hash"],
        request_binding_hash,
    )?;
    object.insert(
        "operationId".to_string(),
        serde_json::Value::String(operation_id.to_string()),
    );
    object.insert(
        "requestBindingHash".to_string(),
        serde_json::Value::String(request_binding_hash.to_string()),
    );
    Ok(())
}

fn validate_existing_operation_metadata(
    metadata: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    expected: &str,
) -> Result<(), PaymentError> {
    for key in keys {
        if let Some(value) = metadata.get(*key) {
            if value.as_str() != Some(expected) {
                return Err(PaymentError::RailError(format!(
                    "payment rail returned mismatched operation metadata field `{key}`"
                )));
            }
        }
    }
    Ok(())
}

fn post_json<B: Serialize, T: DeserializeOwned>(
    http: &ureq::Agent,
    base_url: &str,
    bearer_token: Option<&str>,
    path: &str,
    body: &B,
) -> Result<T, PaymentError> {
    let url = format!("{base_url}{path}");
    let payload = serde_json::to_value(body)
        .map_err(|error| PaymentError::RailError(format!("invalid request payload: {error}")))?;
    let mut request = http.post(&url);
    if let Some(token) = bearer_token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.send_json(payload) {
        Ok(response) => {
            let body = response.into_string().map_err(|error| {
                PaymentError::RailError(format!(
                    "failed to read payment rail response body: {error}"
                ))
            })?;
            serde_json::from_str(&body).map_err(|error| {
                PaymentError::RailError(format!(
                    "failed to decode payment rail response body: {error}"
                ))
            })
        }
        Err(error) => Err(map_http_payment_error(error)),
    }
}

fn build_http_agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build()
}

fn normalize_http_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn default_true() -> bool {
    true
}

fn map_http_payment_error(error: ureq::Error) -> PaymentError {
    match error {
        ureq::Error::Status(402, _response) => PaymentError::InsufficientFunds,
        ureq::Error::Status(status, response) if (400..500).contains(&status) => {
            PaymentError::Declined(response_error_message(response))
        }
        ureq::Error::Status(_, response) => {
            PaymentError::Unavailable(response_error_message(response))
        }
        ureq::Error::Transport(error) => PaymentError::Unavailable(error.to_string()),
    }
}

fn response_error_message(response: ureq::Response) -> String {
    let status_text = response.status_text().to_string();
    match response.into_string() {
        Ok(body) if !body.trim().is_empty() => serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|json| {
                json.get("error")
                    .or_else(|| json.get("message"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or(body),
        _ => status_text,
    }
}

fn merge_json_values(
    base: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (base, extra) {
        (None, extra) => extra,
        (Some(base), None) => Some(base),
        (Some(mut base), Some(extra)) => {
            if let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) {
                for (key, value) in extra_obj {
                    base_obj.insert(key.clone(), value.clone());
                }
                Some(base)
            } else {
                Some(base)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    include!("payment/operation_adapter_tests.inc");

    #[test]
    fn settlement_state_default_fails_closed_to_unavailable() {
        struct BareAdapter;
        impl PaymentAdapter for BareAdapter {
            fn authorize(
                &self,
                _request: &PaymentAuthorizeRequest,
            ) -> Result<PaymentAuthorization, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
            fn capture(
                &self,
                _authorization_id: &str,
                _amount_units: u64,
                _currency: &str,
                _reference: &str,
            ) -> Result<PaymentResult, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
            fn release(
                &self,
                _authorization_id: &str,
                _reference: &str,
            ) -> Result<PaymentResult, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
            fn refund(
                &self,
                _transaction_id: &str,
                _amount_units: u64,
                _currency: &str,
                _reference: &str,
            ) -> Result<PaymentResult, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
        }
        let adapter = BareAdapter;
        assert_eq!(adapter.rail_id(), "payment");
        assert!(!adapter.supports_operation_authorization_recovery());
        assert!(!adapter.supports_operation_payment_mutations());
        // The default forces a fail-closed reconcile incident rather than a
        // silent close for adapters that cannot answer the query.
        match adapter.settlement_state("req-1", None) {
            Err(PaymentError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn prepaid_adapters_answer_settlement_state_without_moving_funds() {
        // The base URLs are never contacted: the prepaid state query is a
        // pure read. With a durable authorization id (proof authorize
        // returned) both adapters report Settled, never Held, because
        // their funds move at authorize: reconciliation must never release
        // a hold discovered through this query.
        let x402 = X402PaymentAdapter::new("http://127.0.0.1:1");
        assert!(x402.supports_operation_authorization_recovery());
        assert!(!x402.supports_operation_payment_mutations());
        match x402
            .settlement_state("req-x", Some("auth-x"))
            .expect("prepaid settlement state answers")
        {
            RailSettlementState::Settled {
                authorization_id,
                result,
            } => {
                assert_eq!(authorization_id, "auth-x");
                assert_eq!(result.transaction_id, "auth-x");
                assert!(matches!(
                    result.settlement_status,
                    RailSettlementStatus::Settled
                ));
            }
            other => panic!("expected Settled, got {other:?}"),
        }

        let acp = AcpPaymentAdapter::new("http://127.0.0.1:1");
        assert_eq!(acp.rail_id(), "acp");
        assert!(acp.supports_operation_authorization_recovery());
        assert!(!acp.supports_operation_payment_mutations());
        match acp
            .settlement_state("req-a", Some("auth-a"))
            .expect("acp settlement state answers")
        {
            RailSettlementState::Settled { result, .. } => {
                assert!(matches!(
                    result.settlement_status,
                    RailSettlementStatus::Settled
                ));
            }
            other => panic!("expected Settled, got {other:?}"),
        }
    }

    #[test]
    fn prepaid_adapters_never_fabricate_settlement_for_a_bare_reference() {
        // The HoldPlaced crash window queries by reference with no
        // authorization id precisely because authorize may never have
        // reached the rail. These thin bridges have no reference-keyed
        // rail query, so the only truthful answer is an error that lands
        // reconciliation in a ReconcileFailed incident - never a
        // fabricated Settled that would emit a reconciliation receipt for
        // money that may never have moved.
        let x402 = X402PaymentAdapter::new("http://127.0.0.1:1");
        match x402.settlement_state("req-x", None) {
            Err(PaymentError::Unavailable(detail)) => {
                assert!(detail.contains("req-x"));
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }

        let acp = AcpPaymentAdapter::new("http://127.0.0.1:1");
        match acp.settlement_state("req-a", None) {
            Err(PaymentError::Unavailable(detail)) => {
                assert!(detail.contains("req-a"));
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn rail_settlement_status_maps_to_canonical_receipt_states() {
        assert_eq!(
            RailSettlementStatus::Authorized.to_receipt_status(),
            SettlementStatus::Pending
        );
        assert_eq!(
            RailSettlementStatus::Captured.to_receipt_status(),
            SettlementStatus::Pending
        );
        assert_eq!(
            RailSettlementStatus::Pending.to_receipt_status(),
            SettlementStatus::Pending
        );
        assert_eq!(
            RailSettlementStatus::Settled.to_receipt_status(),
            SettlementStatus::Settled
        );
        assert_eq!(
            RailSettlementStatus::Released.to_receipt_status(),
            SettlementStatus::Settled
        );
        assert_eq!(
            RailSettlementStatus::Refunded.to_receipt_status(),
            SettlementStatus::Settled
        );
        assert_eq!(
            RailSettlementStatus::Failed.to_receipt_status(),
            SettlementStatus::Failed
        );
    }

    #[test]
    fn authorization_maps_to_receipt_reference_and_state() {
        let pending = PaymentAuthorization {
            authorization_id: "auth_123".to_string(),
            settled: false,
            metadata: serde_json::json!({ "provider": "stripe" }),
        };
        let settled = PaymentAuthorization {
            authorization_id: "auth_456".to_string(),
            settled: true,
            metadata: serde_json::json!({ "provider": "x402" }),
        };

        let pending_receipt = ReceiptSettlement::from_authorization(&pending);
        let settled_receipt = ReceiptSettlement::from_authorization(&settled);

        assert_eq!(
            pending_receipt.payment_reference.as_deref(),
            Some("auth_123")
        );
        assert_eq!(pending_receipt.settlement_status, SettlementStatus::Pending);
        assert_eq!(
            settled_receipt.payment_reference.as_deref(),
            Some("auth_456")
        );
        assert_eq!(settled_receipt.settlement_status, SettlementStatus::Settled);
    }

    #[test]
    fn payment_result_maps_to_receipt_reference_and_state() {
        let result = PaymentResult {
            transaction_id: "txn_123".to_string(),
            settlement_status: RailSettlementStatus::Failed,
            metadata: serde_json::json!({ "provider": "stablecoin" }),
        };

        let receipt = ReceiptSettlement::from_payment_result(&result);

        assert_eq!(receipt.payment_reference.as_deref(), Some("txn_123"));
        assert_eq!(receipt.settlement_status, SettlementStatus::Failed);
    }

    #[test]
    fn x402_adapter_posts_authorize_request_and_returns_settled_payment() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "x402_txn_123",
                "settled": true,
                "metadata": {
                    "network": "base"
                }
            }),
        );
        let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

        let authorization = adapter
            .authorize(&PaymentAuthorizeRequest {
                operation_id: None,
                request_binding_hash: None,
                amount_units: 125,
                currency: "USD".to_string(),
                payer: "agent-1".to_string(),
                payee: "tool-server".to_string(),
                reference: "req-1".to_string(),
                governed: None,
                commerce: None,
            })
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /authorize HTTP/1.1"));
        assert!(request.contains("\"amountUnits\":125"));
        assert!(request.contains("\"currency\":\"USD\""));
        assert!(request.contains("\"payer\":\"agent-1\""));
        assert!(request.contains("\"payee\":\"tool-server\""));
        assert!(request.contains("\"reference\":\"req-1\""));

        assert_eq!(authorization.authorization_id, "x402_txn_123");
        assert!(authorization.settled);
        assert_eq!(authorization.metadata["adapter"], "x402");
        assert_eq!(authorization.metadata["network"], "base");

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn x402_adapter_maps_http_402_to_insufficient_funds() {
        let (url, _request_rx, handle) = spawn_once_json_server(
            402,
            serde_json::json!({
                "error": "insufficient funds"
            }),
        );
        let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

        let error = adapter
            .authorize(&PaymentAuthorizeRequest {
                operation_id: None,
                request_binding_hash: None,
                amount_units: 125,
                currency: "USD".to_string(),
                payer: "agent-1".to_string(),
                payee: "tool-server".to_string(),
                reference: "req-1".to_string(),
                governed: None,
                commerce: None,
            })
            .expect_err("authorization should fail");

        assert!(matches!(error, PaymentError::InsufficientFunds));

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn x402_adapter_uses_custom_path_bearer_token_and_governed_payload() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "x402_txn_custom",
                "settled": true,
                "metadata": {
                    "network": "base-sepolia"
                }
            }),
        );
        let adapter = X402PaymentAdapter::new(url)
            .with_authorize_path("/paywall/authorize")
            .with_bearer_token("secret-token")
            .with_timeout(Duration::from_secs(2));

        let authorization = adapter
            .authorize(&PaymentAuthorizeRequest {
                operation_id: None,
                request_binding_hash: None,
                amount_units: 4200,
                currency: "USD".to_string(),
                payer: "agent-2".to_string(),
                payee: "payments-api".to_string(),
                reference: "req-governed-x402".to_string(),
                governed: Some(GovernedPaymentContext {
                    intent_id: "intent-42".to_string(),
                    intent_hash: "intent-hash-42".to_string(),
                    purpose: "purchase premium dataset".to_string(),
                    server_id: "payments-api".to_string(),
                    tool_name: "fetch_dataset".to_string(),
                    approval_token_id: Some("approval-42".to_string()),
                }),
                commerce: None,
            })
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /paywall/authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer secret-token"));
        assert!(request.contains("\"governed\":{"));
        assert!(request.contains("\"intentId\":\"intent-42\""));
        assert!(request.contains("\"approvalTokenId\":\"approval-42\""));

        assert_eq!(authorization.authorization_id, "x402_txn_custom");
        assert_eq!(authorization.metadata["adapter"], "x402");
        assert_eq!(authorization.metadata["mode"], "prepaid");

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn acp_adapter_posts_authorize_request_with_commerce_context_and_returns_hold() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "acp_hold_123",
                "settled": false,
                "metadata": {
                    "provider": "stripe",
                    "seller": "merchant.example"
                }
            }),
        );
        let adapter = AcpPaymentAdapter::new(url)
            .with_authorize_path("/commerce/authorize")
            .with_bearer_token("acp-secret")
            .with_timeout(Duration::from_secs(2));

        let authorization = adapter
            .authorize(&PaymentAuthorizeRequest {
                operation_id: None,
                request_binding_hash: None,
                amount_units: 4200,
                currency: "USD".to_string(),
                payer: "agent-9".to_string(),
                payee: "merchant.example".to_string(),
                reference: "req-acp-1".to_string(),
                governed: Some(GovernedPaymentContext {
                    intent_id: "intent-acp-1".to_string(),
                    intent_hash: "intent-hash-acp-1".to_string(),
                    purpose: "purchase governed commerce result".to_string(),
                    server_id: "commerce-srv".to_string(),
                    tool_name: "checkout".to_string(),
                    approval_token_id: Some("approval-acp-1".to_string()),
                }),
                commerce: Some(CommercePaymentContext {
                    seller: "merchant.example".to_string(),
                    settlement_destination_ref: "acct:merchant-primary".to_string(),
                    payee_binding_digest: "payee-binding-acp-1".to_string(),
                    pre_action_authority_digest: "approval-digest-acp-1".to_string(),
                    shared_payment_token_id: "spt_live_123".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 5000,
                        currency: "USD".to_string(),
                    }),
                }),
            })
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /commerce/authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer acp-secret"));
        assert!(request.contains("\"commerce\":{"));
        assert!(request.contains("\"seller\":\"merchant.example\""));
        assert!(request.contains("\"sharedPaymentTokenId\":\"spt_live_123\""));
        assert!(request.contains("\"maxAmount\":{"));
        assert!(request.contains("\"units\":5000"));

        assert_eq!(authorization.authorization_id, "acp_hold_123");
        assert!(!authorization.settled);
        assert_eq!(authorization.metadata["adapter"], "acp");
        assert_eq!(authorization.metadata["mode"], "shared_payment_token_hold");
        assert_eq!(authorization.metadata["provider"], "stripe");

        handle.join().expect("server thread should exit cleanly");
    }

    fn spawn_once_json_server(
        status_code: u16,
        body: serde_json::Value,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should expose local address");
        let (request_tx, request_rx) = mpsc::channel();
        let body_text = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let mut header_end = None;
            let mut content_length = 0_usize;

            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server should configure read timeout");
            loop {
                let read = stream
                    .read(&mut chunk)
                    .expect("server should read request bytes");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);

                if header_end.is_none() {
                    header_end = find_header_end(&request);
                    if let Some(end) = header_end {
                        content_length = parse_content_length(&request[..end]);
                    }
                }

                if let Some(end) = header_end {
                    if request.len() >= end + content_length {
                        break;
                    }
                }
            }
            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .expect("request should be sent to test");
            let response = format!(
                "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_text(status_code),
                body_text.len(),
                body_text
            );
            stream
                .write_all(response.as_bytes())
                .expect("server should write response");
        });
        (format!("http://{address}"), request_rx, handle)
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn status_text(status_code: u16) -> &'static str {
        match status_code {
            200 => "OK",
            402 => "Payment Required",
            _ => "Error",
        }
    }
}
