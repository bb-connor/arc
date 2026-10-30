use chio_core::federation::verifier_ledger::oid4vp_requests::{
    Oid4vpRequestHash, Oid4vpRequestId, Oid4vpRequestLedger, Oid4vpRequestRecord,
    Oid4vpRequestStatus, StoredOid4vpRequest,
};
use chio_core::sha256_hex;

use super::{decode_stored, LedgerError, OID4VP_REQUEST};
use crate::{Oid4vpRequestObject, WalletExchangeTransactionState};

#[derive(Debug, Clone)]
pub struct Oid4vpTransactionSnapshot {
    pub request: Oid4vpRequestObject,
    pub request_jwt: String,
    pub transaction: WalletExchangeTransactionState,
}

type Result<T, E> = std::result::Result<T, LedgerError<E>>;
type Row = (Oid4vpRequestId, StoredOid4vpRequest);

pub fn register_oid4vp_request<L: Oid4vpRequestLedger + ?Sized>(
    ledger: &L,
    request: &Oid4vpRequestObject,
    request_jwt: &str,
) -> Result<(), L::Error> {
    let record = Oid4vpRequestRecord {
        request_id: Oid4vpRequestId::parse(request.jti.as_str())?,
        request_hash: Oid4vpRequestHash::parse(sha256_hex(request_jwt.as_bytes()))?,
        request_json: serde_json::to_string(request)?,
        request_jwt: request_jwt.to_owned(),
        issued_at: request.iat,
        expires_at: request.exp,
    };
    ledger.insert(&record).map_err(LedgerError::Store)
}

/// The request and its signed JWT while it is issued and unexpired at `now`.
pub fn fetch_active_oid4vp_request<L: Oid4vpRequestLedger + ?Sized>(
    ledger: &L,
    request_id: &str,
    now: u64,
) -> Result<(Oid4vpRequestObject, String), L::Error> {
    let (_, stored) = issued(ledger, stored(ledger, request_id)?, request_id, now)?;
    Ok((decoded(&stored, request_id)?, stored.record.request_jwt))
}

/// The request with its wallet exchange state at `now`. An issued request
/// past its expiry is marked expired and reported so.
pub fn oid4vp_request_snapshot<L: Oid4vpRequestLedger + ?Sized>(
    ledger: &L,
    request_id: &str,
    now: u64,
) -> Result<Oid4vpTransactionSnapshot, L::Error> {
    let (id, stored) = stored(ledger, request_id)?;
    let request = decoded(&stored, request_id)?;
    let (issued_at, expires_at) = (stored.record.issued_at, stored.record.expires_at);
    let mut status = stored.status;
    if status == Oid4vpRequestStatus::Issued && now > expires_at {
        status = if ledger.expire(&id).map_err(LedgerError::Store)? {
            Oid4vpRequestStatus::Expired
        } else {
            self::stored(ledger, request_id)?.1.status
        };
    }
    let transaction = match status {
        Oid4vpRequestStatus::Issued => {
            WalletExchangeTransactionState::issued(request_id, request_id, issued_at, expires_at)
        }
        Oid4vpRequestStatus::Consumed { at } => WalletExchangeTransactionState::consumed(
            request_id, request_id, issued_at, expires_at, at,
        ),
        Oid4vpRequestStatus::Expired => {
            WalletExchangeTransactionState::expired(request_id, request_id, issued_at, expires_at)
        }
    };
    transaction.validate()?;
    Ok(Oid4vpTransactionSnapshot {
        request,
        request_jwt: stored.record.request_jwt,
        transaction,
    })
}

pub fn consume_oid4vp_request<L: Oid4vpRequestLedger + ?Sized>(
    ledger: &L,
    request: &Oid4vpRequestObject,
    request_jwt: &str,
    now: u64,
) -> Result<(), L::Error> {
    let request_id = request.jti.as_str();
    let row = stored(ledger, request_id)?;
    if row.1.record.request_hash.as_str() != sha256_hex(request_jwt.as_bytes()) {
        return Err(LedgerError::Mismatch(OID4VP_REQUEST, request_id.into()));
    }
    let (id, _) = issued(ledger, row, request_id, now)?;
    if !ledger.consume(&id, now).map_err(LedgerError::Store)? {
        return Err(LedgerError::Contended(OID4VP_REQUEST, request_id.into()));
    }
    Ok(())
}

/// `row` while it is issued and unexpired at `now`. An issued row past its
/// expiry is marked expired and refused.
fn issued<L: Oid4vpRequestLedger + ?Sized>(
    ledger: &L,
    (id, stored): Row,
    request_id: &str,
    now: u64,
) -> Result<Row, L::Error> {
    match stored.status {
        Oid4vpRequestStatus::Issued if now > stored.record.expires_at => {
            ledger.expire(&id).map_err(LedgerError::Store)?;
            Err(LedgerError::ExpiredInUse(OID4VP_REQUEST, request_id.into()))
        }
        Oid4vpRequestStatus::Issued => Ok((id, stored)),
        Oid4vpRequestStatus::Consumed { .. } => Err(LedgerError::AlreadyConsumed(
            OID4VP_REQUEST,
            request_id.into(),
        )),
        Oid4vpRequestStatus::Expired => Err(LedgerError::AlreadyExpired(
            OID4VP_REQUEST,
            request_id.into(),
        )),
    }
}

/// An identifier no ledger could hold is not registered.
fn stored<L: Oid4vpRequestLedger + ?Sized>(ledger: &L, request_id: &str) -> Result<Row, L::Error> {
    let not_registered = || LedgerError::NotRegistered(OID4VP_REQUEST, request_id.into());
    let id = Oid4vpRequestId::parse(request_id).map_err(|_| not_registered())?;
    let stored = ledger
        .get(&id)
        .map_err(LedgerError::Store)?
        .ok_or_else(not_registered)?;
    Ok((id, stored))
}

fn decoded<E>(stored: &StoredOid4vpRequest, request_id: &str) -> Result<Oid4vpRequestObject, E> {
    let request: Oid4vpRequestObject = decode_stored(&stored.record.request_json)?;
    let record = &stored.record;
    if request.jti != request_id
        || request.iat != record.issued_at
        || request.exp != record.expires_at
    {
        return Err(LedgerError::Binding("request_id/issued_at/expires_at"));
    }
    Ok(request)
}
