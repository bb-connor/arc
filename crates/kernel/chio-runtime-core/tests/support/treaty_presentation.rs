//! Receiver provisioning for trusted test fixtures. Never use this helper to
//! provision records from an incoming request in a deployed receiver.

use chio_federation::bilateral_dsse::DsseEnvelope;
use chio_runtime_core::{RuntimeTreatyGovernanceRecord, RuntimeTreatyLeaseRecord};

pub fn records(
    envelope: &DsseEnvelope,
) -> Result<(RuntimeTreatyLeaseRecord, RuntimeTreatyGovernanceRecord), Box<dyn std::error::Error>> {
    let (statement, _) = envelope.decode_statement()?;
    let lease = statement
        .predicate
        .capability_lease_ref
        .ok_or("fixture lease missing")?;
    let receipt = statement
        .predicate
        .governance_receipt_ref
        .ok_or("fixture governance missing")?;
    let valid_until_unix_ms = lease.expires_at_unix_ms;
    Ok((
        RuntimeTreatyLeaseRecord {
            lease,
            valid_from_unix_ms: 1_800_000_000_000,
        },
        RuntimeTreatyGovernanceRecord {
            receipt,
            valid_from_unix_ms: 1_800_000_000_000,
            valid_until_unix_ms,
        },
    ))
}
