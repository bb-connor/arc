use chio_federation::verifier_ledger::oid4vp_requests::{
    Oid4vpRequestHash, Oid4vpRequestId, Oid4vpRequestLedger, Oid4vpRequestRecord,
    Oid4vpRequestStatus, StoredOid4vpRequest,
};
use rusqlite::{params, OptionalExtension, Row};

use super::{
    duplicate_or, ledger_fault, stored_u64, LedgerFault, PassportVerifierStoreError, Result,
    SqlitePassportVerifierStore,
};

type PortResult<T> = std::result::Result<T, LedgerFault>;
use crate::integer::checked;

pub(super) const SCHEMA: &str = include_str!("oid4vp_requests.sql");

pub(super) const INSERT: &str = "INSERT INTO passport_oid4vp_transactions (
    request_id, request_hash, request_json, request_jwt, issued_at, expires_at, status
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'issued')";

pub(super) const SELECT: &str =
    "SELECT request_id, request_hash, request_json, request_jwt, issued_at, expires_at, status,
     consumed_at
     FROM passport_oid4vp_transactions
     WHERE request_id = ?1";

pub(super) const EXPIRE: &str = "UPDATE passport_oid4vp_transactions
     SET status = 'expired'
     WHERE request_id = ?1 AND status = 'issued'";

pub(super) const CONSUME: &str = "UPDATE passport_oid4vp_transactions
     SET status = 'consumed', consumed_at = ?2
     WHERE request_id = ?1 AND status = 'issued'";

impl SqlitePassportVerifierStore {
    fn insert_request(&self, record: &Oid4vpRequestRecord) -> Result<()> {
        let issued_at: i64 = checked(record.issued_at)?;
        let expires_at: i64 = checked(record.expires_at)?;
        self.transact(|transaction| {
            transaction
                .execute(
                    INSERT,
                    params![
                        record.request_id.as_str(),
                        record.request_hash.as_str(),
                        record.request_json,
                        record.request_jwt,
                        issued_at,
                        expires_at,
                    ],
                )
                .map_err(|error| duplicate_or(error, record.request_id.as_str()))?;
            Ok(())
        })
    }

    fn get_request(&self, request_id: &Oid4vpRequestId) -> Result<Option<StoredOid4vpRequest>> {
        self.read(|connection| {
            connection
                .query_row(SELECT, [request_id.as_str()], |row| Ok(stored(row)))
                .optional()?
                .transpose()
        })
    }

    fn expire_request(&self, request_id: &Oid4vpRequestId) -> Result<bool> {
        self.transact(|transaction| Ok(transaction.execute(EXPIRE, [request_id.as_str()])? == 1))
    }

    fn consume_request(&self, request_id: &Oid4vpRequestId, at: u64) -> Result<bool> {
        let at: i64 = checked(at)?;
        self.transact(|transaction| {
            Ok(transaction.execute(CONSUME, params![request_id.as_str(), at])? == 1)
        })
    }
}

impl Oid4vpRequestLedger for SqlitePassportVerifierStore {
    type Error = LedgerFault;

    fn insert(&self, record: &Oid4vpRequestRecord) -> PortResult<()> {
        self.insert_request(record).map_err(ledger_fault)
    }

    fn get(&self, request_id: &Oid4vpRequestId) -> PortResult<Option<StoredOid4vpRequest>> {
        self.get_request(request_id).map_err(ledger_fault)
    }

    fn expire(&self, request_id: &Oid4vpRequestId) -> PortResult<bool> {
        self.expire_request(request_id).map_err(ledger_fault)
    }

    fn consume(&self, request_id: &Oid4vpRequestId, at: u64) -> PortResult<bool> {
        self.consume_request(request_id, at).map_err(ledger_fault)
    }
}

fn stored(row: &Row<'_>) -> Result<StoredOid4vpRequest> {
    Ok(StoredOid4vpRequest {
        record: Oid4vpRequestRecord {
            request_id: Oid4vpRequestId::parse(row.get::<_, String>(0)?)?,
            request_hash: Oid4vpRequestHash::parse(row.get::<_, String>(1)?)?,
            request_json: row.get(2)?,
            request_jwt: row.get(3)?,
            issued_at: stored_u64(row.get(4)?)?,
            expires_at: stored_u64(row.get(5)?)?,
        },
        status: status_from_row(&row.get::<_, String>(6)?, row.get(7)?)?,
    })
}

fn status_from_row(label: &str, consumed_at: Option<i64>) -> Result<Oid4vpRequestStatus> {
    match (label, consumed_at) {
        ("issued", None) => Ok(Oid4vpRequestStatus::Issued),
        ("consumed", Some(at)) => Ok(Oid4vpRequestStatus::Consumed {
            at: stored_u64(at)?,
        }),
        ("expired", None) => Ok(Oid4vpRequestStatus::Expired),
        _ => Err(PassportVerifierStoreError::InvalidRow),
    }
}
