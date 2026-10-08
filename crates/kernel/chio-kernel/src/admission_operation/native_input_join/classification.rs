//! Affine acknowledgment of the owning writer's exact classified input join.
use super::*;
use crate::admission_operation::{
    AdmissionOperationV1, AdmissionRecoveryLease, NativeSecurityAuthorityBindingV1,
};
use std::cell::Cell;

/// Minted only by the Kernel's original input callback. It authorizes one
/// classified acknowledgment, never a native mutation, capture or tool effect.
/// A caller cannot construct or decode a replacement authority.
///
/// ```compile_fail
/// use chio_kernel::admission_operation::NativeSecurityInputClassificationAuthority;
/// let _: Result<NativeSecurityInputClassificationAuthority<'_>, _> =
///     serde_json::from_str("{}");
/// ```
pub struct NativeSecurityInputClassificationAuthority<'call> {
    operation: &'call AdmissionOperationV1,
    lease: &'call AdmissionRecoveryLease,
    binding: &'call NativeSecurityAuthorityBindingV1,
    context: &'call crate::SecurityInvocationContext,
    input: &'call NativeSecurityInputJoinRequestV1,
    request: &'call crate::ToolCallRequest,
    trusted_now_unix_ms: u64,
    finished: Cell<bool>,
}

enum Classification {
    Eligible,
    Refused,
}

/// One writer acknowledgment bound to the Kernel's affine callback. The join
/// is immutable historical data; neither classification grants execution.
///
/// ```compile_fail
/// use chio_kernel::admission_operation::NativeSecurityInputJoinOutcome;
/// let _: Result<NativeSecurityInputJoinOutcome<'_>, _> = serde_json::from_str("{}");
/// ```
pub struct NativeSecurityInputJoinOutcome<'call> {
    authority: &'call NativeSecurityInputClassificationAuthority<'call>,
    record: NativeSecurityInputJoinRecordV1,
    classification: Classification,
}

impl<'call> NativeSecurityInputClassificationAuthority<'call> {
    pub(crate) fn new(
        operation: &'call AdmissionOperationV1,
        lease: &'call AdmissionRecoveryLease,
        binding: &'call NativeSecurityAuthorityBindingV1,
        context: &'call crate::SecurityInvocationContext,
        input: &'call NativeSecurityInputJoinRequestV1,
        request: &'call crate::ToolCallRequest,
        trusted_now_unix_ms: u64,
    ) -> Self {
        Self {
            operation,
            lease,
            binding,
            context,
            input,
            request,
            trusted_now_unix_ms,
            finished: Cell::new(false),
        }
    }

    pub fn operation(&self) -> &AdmissionOperationV1 {
        self.operation
    }

    pub fn lease(&self) -> &AdmissionRecoveryLease {
        self.lease
    }

    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        self.binding
    }

    pub fn context(&self) -> &crate::SecurityInvocationContext {
        self.context
    }

    pub fn input(&self) -> &NativeSecurityInputJoinRequestV1 {
        self.input
    }

    /// Borrow the actual request from this original Kernel callback. Retained
    /// history deliberately strips transient credentials and cannot supply it.
    /// This read-only value cannot authorize a join, capture or external effect.
    pub fn request(&self) -> &crate::ToolCallRequest {
        self.request
    }

    pub const fn trusted_now_unix_ms(&self) -> u64 {
        self.trusted_now_unix_ms
    }

    pub fn eligible(
        &'call self,
        record: NativeSecurityInputJoinRecordV1,
    ) -> Result<NativeSecurityInputJoinOutcome<'call>, AdmissionOperationStoreError> {
        self.finish(record, Classification::Eligible)
    }

    pub fn refused(
        &'call self,
        record: NativeSecurityInputJoinRecordV1,
    ) -> Result<NativeSecurityInputJoinOutcome<'call>, AdmissionOperationStoreError> {
        self.finish(record, Classification::Refused)
    }

    fn finish(
        &'call self,
        record: NativeSecurityInputJoinRecordV1,
        classification: Classification,
    ) -> Result<NativeSecurityInputJoinOutcome<'call>, AdmissionOperationStoreError> {
        if self.finished.replace(true) {
            return Err(invalid(
                "classified input acknowledgment was already issued",
            ));
        }
        record.validate()?;
        if record.input != *self.input
            || record.join.binding != *self.binding
            || record.join.operation_id != *self.operation.binding().operation_id()
        {
            return Err(invalid(
                "classified input acknowledgment changed its original",
            ));
        }
        Ok(NativeSecurityInputJoinOutcome {
            authority: self,
            record,
            classification,
        })
    }
}

impl NativeSecurityInputJoinOutcome<'_> {
    pub fn record(&self) -> &NativeSecurityInputJoinRecordV1 {
        &self.record
    }

    pub fn is_refused(&self) -> bool {
        matches!(self.classification, Classification::Refused)
    }

    pub(crate) fn belongs_to(
        &self,
        authority: &NativeSecurityInputClassificationAuthority<'_>,
    ) -> bool {
        std::ptr::eq(self.authority, authority) && authority.finished.get()
    }
}

impl std::fmt::Debug for NativeSecurityInputClassificationAuthority<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityInputClassificationAuthority")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeSecurityInputJoinOutcome<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityInputJoinOutcome")
            .finish_non_exhaustive()
    }
}
