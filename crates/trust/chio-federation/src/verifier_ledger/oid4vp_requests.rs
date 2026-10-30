/// An OID4VP request's `jti`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4vpRequestId(String);
ledger_text!(Oid4vpRequestId, identifier, "request_id");

/// SHA-256 of the signed request JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4vpRequestHash(String);
ledger_text!(Oid4vpRequestHash, digest, "request_hash");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oid4vpRequestStatus {
    Issued,
    Consumed { at: u64 },
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4vpRequestRecord {
    pub request_id: Oid4vpRequestId,
    pub request_hash: Oid4vpRequestHash,
    pub request_json: String,
    pub request_jwt: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOid4vpRequest {
    pub record: Oid4vpRequestRecord,
    pub status: Oid4vpRequestStatus,
}

/// Every method is one atomic unit; `expire` and `consume` move an issued
/// row only and return whether it was issued.
pub trait Oid4vpRequestLedger {
    type Error;

    /// Refuses a duplicate identifier.
    fn insert(&self, record: &Oid4vpRequestRecord) -> Result<(), Self::Error>;

    fn get(&self, request_id: &Oid4vpRequestId)
        -> Result<Option<StoredOid4vpRequest>, Self::Error>;

    fn expire(&self, request_id: &Oid4vpRequestId) -> Result<bool, Self::Error>;

    fn consume(&self, request_id: &Oid4vpRequestId, at: u64) -> Result<bool, Self::Error>;
}
