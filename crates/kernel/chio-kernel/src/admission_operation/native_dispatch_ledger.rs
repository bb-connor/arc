//! Native dispatch preparation history, never a capture or execution permit.

use super::{AdmissionDigest, AdmissionOperationId, NativeSecurityEgressContext};

/// Borrowed input from the live policy resolver. The store independently checks
/// original admission, grant selection, current lease and physical participants.
/// Canonical policy bytes are private evidence, not deserialized authority.
pub struct NativeSecurityDispatchLedgerContext<'a> {
    pub custody: NativeSecurityEgressContext<'a>,
    pub grant_index: usize,
    pub policy_json: &'a [u8],
}

/// Fenced readback of one immutable preparation. A record may outlive its lease,
/// policy deadline and participants. Neither construction nor replay authorizes
/// budget capture, connector invocation or release of a retained credential.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityDispatchLedgerRecordV1 {
    pub operation_id: AdmissionOperationId,
    pub record_digest: AdmissionDigest,
    pub canonical_record: Vec<u8>,
}

impl std::fmt::Debug for NativeSecurityDispatchLedgerContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityDispatchLedgerContext")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeSecurityDispatchLedgerRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityDispatchLedgerRecordV1")
            .field("encoded_bytes", &self.canonical_record.len())
            .finish_non_exhaustive()
    }
}
