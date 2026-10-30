//! Single-use rules for a verifier's presentation challenges and OID4VP
//! requests, over the `chio_federation::verifier_ledger` ports.

use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use chio_core::federation::verifier_ledger::LedgerFieldError;
use serde::de::DeserializeOwned;

use crate::CredentialError;

mod challenges;
mod oid4vp;

pub use challenges::{
    challenge_identifier, consume_presentation_challenge, fetch_active_presentation_challenge,
    register_presentation_challenge, ChallengeConsumer,
};
pub use oid4vp::{
    consume_oid4vp_request, fetch_active_oid4vp_request, oid4vp_request_snapshot,
    register_oid4vp_request, Oid4vpTransactionSnapshot,
};

const CHALLENGE: &str = "challenge";
const OID4VP_REQUEST: &str = "OID4VP request";

#[derive(Debug, thiserror::Error)]
pub enum LedgerError<E> {
    #[error("{0} `{1}` is not registered in the verifier store")]
    NotRegistered(&'static str, String),
    #[error("{0} `{1}` has already been consumed")]
    AlreadyConsumed(&'static str, String),
    #[error("{0} `{1}` has already expired")]
    AlreadyExpired(&'static str, String),
    #[error("{0} `{1}` expired before it could be used")]
    ExpiredInUse(&'static str, String),
    #[error("stored {0} `{1}` does not match the presented one")]
    Mismatch(&'static str, String),
    #[error("{0} `{1}` could not be consumed safely")]
    Contended(&'static str, String),
    #[error("record storage binding does not match {0}")]
    Binding(&'static str),
    #[error(transparent)]
    Field(#[from] LedgerFieldError),
    #[error(transparent)]
    Decode(#[from] UntrustedJsonError),
    #[error("{0}")]
    Encode(#[from] serde_json::Error),
    #[error("{0}")]
    Canonical(#[from] chio_core::Error),
    #[error("{0}")]
    Credential(#[from] CredentialError),
    #[error("{0}")]
    Store(#[source] E),
}

const MAX_LEDGER_JSON_BYTES: usize = 16 * 1024 * 1024;

fn decode_stored<T: DeserializeOwned>(json: &str) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(json.as_bytes(), MAX_LEDGER_JSON_BYTES)?.decode_signed()
}
