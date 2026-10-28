use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommerceOrderError {
    #[error("commerce input rejected: {0}")]
    Input(#[source] chio_core_types::canonical::SharedUntrustedJsonError),
    #[error("commerce evidence exceeds the verification budget")]
    EvidenceLimit,
    #[error("unsupported commerce schema for {field}: {schema}")]
    UnsupportedSchema { field: &'static str, schema: String },
    #[error("invalid commerce artifact {field}: {message}")]
    InvalidArtifact {
        field: &'static str,
        message: String,
    },
    #[error("{field} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        field: String,
        expected: String,
        actual: String,
    },
    #[error("commerce replay failed: {0}")]
    ReplayFailed(String),
    #[error("commerce replay failed: {0}")]
    ReplayDigestMismatch(String),
    #[error("commerce replay failed: {0}")]
    ReplaySignatureInvalid(String),
    #[error("commerce payment failed: {0}")]
    PaymentFailed(String),
    #[error("commerce payment failed: {0}")]
    PaymentDigestMismatch(String),
    #[error("commerce payment failed: {0}")]
    PaymentSignatureInvalid(String),
    #[error("commerce mandate failed: {0}")]
    MandateFailed(String),
    #[error("commerce mandate failed: {0}")]
    MandateDigestMismatch(String),
    #[error("commerce provider trust failed: {0}")]
    ProviderTrustFailed(String),
    #[error("commerce provider trust failed: {0}")]
    ProviderTrustSignatureInvalid(String),
    #[error("commerce settlement failed: {0}")]
    SettlementFailed(String),
    #[error("commerce settlement failed: {0}")]
    SettlementDigestMismatch(String),
    #[error("commerce settlement failed: {0}")]
    SettlementSignatureInvalid(String),
    #[error("commerce coverage failed: {0}")]
    CoverageFailed(String),
    #[error("commerce escrow denied: {0}")]
    Escrow(#[from] CommerceEscrowError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommerceEscrowError {
    #[error("order state {0} does not allow settlement-packet assembly")]
    AcceptStateNotAllowed(String),
    #[error("offer token signature is invalid")]
    OfferSignatureInvalid,
    #[error("offer token is outside its validity window")]
    OfferOutsideValidityWindow,
    #[error("offer token is issued by its own subject")]
    OfferSelfIssued,
    #[error("offer token issuer is not the order merchant key")]
    OfferIssuerNotMerchant,
    #[error("escrow acceptance is not signed by the offer token subject")]
    AcceptorNotSubject,
    #[error("unsupported escrow acceptance schema: {0}")]
    AcceptanceSchemaUnsupported(String),
    #[error("escrow acceptance signature is invalid")]
    AcceptanceSignatureInvalid,
    #[error("escrow acceptance {0} does not match the order offer")]
    AcceptanceUnbound(&'static str),
    #[error("offer liability is invalid: {0}")]
    OfferLiabilityInvalid(&'static str),
    #[error("offer liability currency does not match the quote currency")]
    LiabilityCurrencyMismatch,
    #[error("offer liability does not equal the quote amount")]
    LiabilityQuoteMismatch,
    #[error("no trusted reservation authority is pinned")]
    NoTrustedReservationAuthority,
    #[error("reservation receipt signer is not a pinned reservation authority")]
    ReservationSignerUntrusted,
    #[error("reservation receipt signature is invalid")]
    ReservationSignatureInvalid,
    #[error("unsupported reservation receipt schema: {0}")]
    ReservationSchemaUnsupported(String),
    #[error("reservation receipt id is empty")]
    ReservationIdEmpty,
    #[error("reservation receipt {0} does not match the order offer")]
    ReservationUnbound(&'static str),
    #[error("reservation currency does not match the offer liability")]
    ReservationCurrencyMismatch,
    #[error("reservation does not cover the offer liability")]
    ReservationUnderCollateralized,
    #[error("settlement dispatch {0} is empty")]
    DispatchFieldEmpty(&'static str),
    #[error("settlement dispatch status must be dispatched, got {0}")]
    DispatchStatusNotDispatched(String),
    #[error("settlement dispatch issued_at is not an RFC3339 timestamp")]
    DispatchIssuedAtInvalid,
    #[error("settlement packet signing failed: {0}")]
    SettlementSigningFailed(String),
    #[error("escrow canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("unsupported escrow ledger schema: {0}")]
    LedgerSchemaUnsupported(String),
    #[error("escrow ledger amount is zero")]
    LedgerZeroAmount,
    #[error("escrow ledger custody account {0} is not the fixed custody account")]
    LedgerCustodyAccount(String),
    #[error("escrow ledger depositor, beneficiary, and custody accounts are not distinct")]
    LedgerAccountsNotDistinct,
    #[error("escrow ledger legs are not the canonical legs for its status")]
    LedgerLegsNotCanonical,
    #[error("escrow ledger is not locked")]
    LedgerNotLocked,
    #[error("escrow ledger {0} does not match the order context")]
    LedgerOrderBinding(&'static str),
    #[error("order context pins an escrow digest but no escrow ledger was supplied")]
    LedgerMissing,
    #[error("escrow ledger supplied for an order context without an escrow digest")]
    LedgerUnpinned,
    #[error("order state {0} cannot carry an escrow digest")]
    LedgerPinnedBeforeAccept(String),
    #[error("order state {state} requires a {required:?} escrow ledger")]
    LedgerStatusMismatch {
        state: String,
        required: crate::escrow::CommerceEscrowStatus,
    },
    #[error("acceptance escrow digest does not match its ledger")]
    AcceptanceDigestMismatch,
    #[error("accepted context does not pin the acceptance escrow digest")]
    AcceptedContextUnbound,
    #[error("no trusted settlement authority is pinned")]
    NoTrustedSettlementAuthority,
    #[error("settlement packet signer is not a pinned settlement authority")]
    SettlementSignerUntrusted,
    #[error("settlement packet signature is invalid")]
    SettlementSignatureInvalid,
    #[error("settlement packet does not match the accepted context {0}")]
    SettlementPacketUnbound(&'static str),
    #[error("release context {0} does not match the accepted context")]
    ReleaseContextMismatch(String),
    #[error("order state {0} does not allow settlement reconciliation")]
    ReleaseStateNotAllowed(String),
    #[error("no trusted execution authority is pinned")]
    NoTrustedExecutionAuthority,
    #[error("execution instruction signer is not a pinned execution authority")]
    ExecutionSignerUntrusted,
    #[error("execution instruction signature is invalid")]
    ExecutionSignatureInvalid,
    #[error("execution instruction is invalid: {0}")]
    ExecutionInvalid(String),
    #[error("execution instruction action is not release_reserve")]
    ExecutionActionNotRelease,
    #[error("execution instruction is not reconciled as matched")]
    ExecutionNotMatched,
    #[error("execution instruction {0} does not match the locked escrow")]
    ExecutionUnbound(&'static str),
    #[error("execution instruction {0} is after the release time")]
    ExecutionAfterRelease(&'static str),
}
