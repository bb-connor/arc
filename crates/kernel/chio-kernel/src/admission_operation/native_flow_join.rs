//! Store evidence for a monotone join, never authority to execute or release.

use super::{AdmissionDigest, AdmissionOperationId, NativeSecurityAuthorityBindingV1};
use chio_security_types::ports::{FlowJoinRequest, FlowStateSnapshot};

/// Data returned by a fenced store snapshot. Constructing this record grants no
/// authority. The kernel compares every field with its call-scoped command and
/// independently reads the committed history before continuing admission.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityFlowJoinRecordV1 {
    pub binding: NativeSecurityAuthorityBindingV1,
    pub operation_id: AdmissionOperationId,
    pub command: FlowJoinRequest,
    pub snapshot: FlowStateSnapshot,
    pub mutation_digest: AdmissionDigest,
}

impl std::fmt::Debug for NativeSecurityFlowJoinRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityFlowJoinRecordV1")
            .finish_non_exhaustive()
    }
}
