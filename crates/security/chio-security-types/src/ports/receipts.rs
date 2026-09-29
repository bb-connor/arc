use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::CanonicalBody;
use super::TenantId;
use super::RecordId;
use super::OpaqueReceiptRef;
use super::PortResult;


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAppendRequest {
    pub tenant_id: TenantId,
    pub evidence_type: RecordId,
    pub evidence_id: OpaqueReceiptRef,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReceiptRecord {
    pub receipt: ReceiptAppendRequest,
    pub durable_record_hash: Digest32,
}

#[cfg(feature = "std")]
pub trait SecurityReceiptSink: Send + Sync {
    fn ensure_receipts_ready(&self) -> PortResult<()>;
    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef>;
}

/// Receipt sink contract required by durable state machines. A successful
/// append is not authoritative until `load_exact` returns the identical
/// logical append request from durable signed storage.
#[cfg(feature = "std")]
pub trait ExactSecurityReceiptSink: SecurityReceiptSink {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>>;
}
