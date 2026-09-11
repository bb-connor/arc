//! Portable egress commands and historical evidence, not execution authority.

use super::{
    AdmissionDigest, AdmissionOperationId, AdmissionOperationV1, AdmissionRecoveryLease,
    NativeSecurityAuthorityBindingV1,
};
use crate::{SecurityInvocationContext, ToolCallRequest};
use chio_security_types::ports::{CommittedEgressFence, EgressFence};

/// Borrowed inputs to one store command. Constructing this value grants no
/// custody: the store must verify the actual operation, original selection,
/// current recovery lease, live request and independently initialized authority.
/// The complete live request is borrowed, never retained in historical evidence.
pub struct NativeSecurityEgressContext<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub lease: &'a AdmissionRecoveryLease,
    pub binding: &'a NativeSecurityAuthorityBindingV1,
    pub security_context: &'a SecurityInvocationContext,
    pub request: &'a ToolCallRequest,
    pub trusted_now_unix_ms: u64,
}

impl std::fmt::Debug for NativeSecurityEgressContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityEgressContext")
            .finish_non_exhaustive()
    }
}

/// Original acquisition evidence. This fence may since have expired or become
/// stale, and the event digest is not a lease or permission to dispatch.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityEgressAcquisitionV1 {
    pub fence: EgressFence,
    pub event_digest: AdmissionDigest,
}

impl std::fmt::Debug for NativeSecurityEgressAcquisitionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityEgressAcquisitionV1")
            .finish_non_exhaustive()
    }
}

/// Later commitment evidence, retaining its exact acquisition predecessor.
/// A commitment records historical custody, not successful tool execution.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityEgressCommitmentV1 {
    pub commitment: CommittedEgressFence,
    pub event_digest: AdmissionDigest,
    pub acquisition_digest: AdmissionDigest,
}

impl std::fmt::Debug for NativeSecurityEgressCommitmentV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityEgressCommitmentV1")
            .finish_non_exhaustive()
    }
}

/// Both egress phases from one fenced, anchored snapshot. The kernel must
/// compare this data with its original command, request digest and expected
/// operation. A later commitment must never hide or replace the acquisition.
/// Neither constructing nor reading this record grants fresh authority.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityEgressHistoryV1 {
    pub binding: NativeSecurityAuthorityBindingV1,
    pub operation_id: AdmissionOperationId,
    pub live_request_hash: AdmissionDigest,
    pub acquisition: NativeSecurityEgressAcquisitionV1,
    pub commitment: Option<NativeSecurityEgressCommitmentV1>,
}

impl std::fmt::Debug for NativeSecurityEgressHistoryV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityEgressHistoryV1")
            .finish_non_exhaustive()
    }
}
