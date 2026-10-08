//! Fixed private host-log classes for a failed native dispatch. A class names
//! the existing check or stage that refused. It carries no error text and has
//! no effect on the public error, receipt, recovery state or check order.
use crate::admission_operation::AdmissionCaptureError;

/// Deadline classes are assigned only where an existing comparison against
/// the live deadline refused. Every other class names a stage or a typed store
/// category, never a cause inferred from a later clock or store read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeDispatchFault {
    /// The hook failed before entering any kernel retention or capture step.
    HookBeforeCapture,
    /// The hook failed after entering kernel authority without a recorded failure.
    HookAfterAuthorityEntry,
    /// The hook returned success after a kernel step had failed.
    HookSuppressedCaptureFailure,
    /// The hook returned success without capturing original custody.
    HookSkippedCapture,
    /// Retention refused before its first durable custody write.
    RetentionBeforeStore,
    /// Retention found its live deadline at or before trusted time.
    RetentionDeadline,
    /// Retention failed at or after its first durable custody write.
    RetentionStore,
    /// Capture refused before entering its physical store transaction.
    CaptureBeforeStore,
    CaptureStorePanicked,
    CaptureStoreFenced,
    CaptureStoreOutcomeUnknown,
    /// The store refused the physical transaction for any other typed reason.
    CaptureStoreRejected,
    /// The committed acknowledgement or its physical readback was refused.
    CaptureReadback,
    /// Handoff refused before or at entry, other than by its deadline.
    HandoffEntry,
    HandoffDeadlineAtEntry,
    /// The physical capture readback was unreadable, absent or changed.
    HandoffReadback,
    /// The flow observation or its trusted time sample was refused.
    HandoffFlow,
    HandoffDeadlineAfterReadback,
    /// Release custody could not be established for the captured owner.
    HandoffCustody,
}

impl NativeDispatchFault {
    pub(super) fn capture_store(error: &AdmissionCaptureError) -> Self {
        match error {
            AdmissionCaptureError::Fenced => Self::CaptureStoreFenced,
            AdmissionCaptureError::OutcomeUnknown(_) => Self::CaptureStoreOutcomeUnknown,
            AdmissionCaptureError::Unavailable(_)
            | AdmissionCaptureError::Invariant(_)
            | AdmissionCaptureError::Operation(_) => Self::CaptureStoreRejected,
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::HookBeforeCapture => "hook_before_capture",
            Self::HookAfterAuthorityEntry => "hook_after_authority_entry",
            Self::HookSuppressedCaptureFailure => "hook_suppressed_capture_failure",
            Self::HookSkippedCapture => "hook_skipped_capture",
            Self::RetentionBeforeStore => "retention_before_store",
            Self::RetentionDeadline => "retention_deadline",
            Self::RetentionStore => "retention_store",
            Self::CaptureBeforeStore => "capture_before_store",
            Self::CaptureStorePanicked => "capture_store_panicked",
            Self::CaptureStoreFenced => "capture_store_fenced",
            Self::CaptureStoreOutcomeUnknown => "capture_store_outcome_unknown",
            Self::CaptureStoreRejected => "capture_store_rejected",
            Self::CaptureReadback => "capture_readback",
            Self::HandoffEntry => "handoff_entry",
            Self::HandoffDeadlineAtEntry => "handoff_deadline_at_entry",
            Self::HandoffReadback => "handoff_readback",
            Self::HandoffFlow => "handoff_flow",
            Self::HandoffDeadlineAfterReadback => "handoff_deadline_after_readback",
            Self::HandoffCustody => "handoff_custody",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::admission_operation::AdmissionCaptureError;

    use super::NativeDispatchFault as Fault;

    const ALL: [Fault; 19] = [
        Fault::HookBeforeCapture,
        Fault::HookAfterAuthorityEntry,
        Fault::HookSuppressedCaptureFailure,
        Fault::HookSkippedCapture,
        Fault::RetentionBeforeStore,
        Fault::RetentionDeadline,
        Fault::RetentionStore,
        Fault::CaptureBeforeStore,
        Fault::CaptureStorePanicked,
        Fault::CaptureStoreFenced,
        Fault::CaptureStoreOutcomeUnknown,
        Fault::CaptureStoreRejected,
        Fault::CaptureReadback,
        Fault::HandoffEntry,
        Fault::HandoffDeadlineAtEntry,
        Fault::HandoffReadback,
        Fault::HandoffFlow,
        Fault::HandoffDeadlineAfterReadback,
        Fault::HandoffCustody,
    ];

    #[test]
    fn native_dispatch_fault_store_errors_keep_their_typed_categories() {
        let private = "private store detail that must not become a class";
        for (error, expected) in [
            (AdmissionCaptureError::Fenced, "capture_store_fenced"),
            (
                AdmissionCaptureError::OutcomeUnknown(private.to_owned()),
                "capture_store_outcome_unknown",
            ),
            (
                AdmissionCaptureError::Unavailable(private.to_owned()),
                "capture_store_rejected",
            ),
            (
                AdmissionCaptureError::Invariant(private.to_owned()),
                "capture_store_rejected",
            ),
        ] {
            assert_eq!(Fault::capture_store(&error).as_str(), expected);
        }
    }

    #[test]
    fn native_dispatch_fault_vocabulary_is_unique_fixed_tokens() {
        let names = ALL.map(Fault::as_str);
        // The operator qualification allowlist mirrors exactly these names.
        assert_eq!(
            names,
            [
                "hook_before_capture",
                "hook_after_authority_entry",
                "hook_suppressed_capture_failure",
                "hook_skipped_capture",
                "retention_before_store",
                "retention_deadline",
                "retention_store",
                "capture_before_store",
                "capture_store_panicked",
                "capture_store_fenced",
                "capture_store_outcome_unknown",
                "capture_store_rejected",
                "capture_readback",
                "handoff_entry",
                "handoff_deadline_at_entry",
                "handoff_readback",
                "handoff_flow",
                "handoff_deadline_after_readback",
                "handoff_custody",
            ]
        );
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        for name in names {
            assert!(
                (1..=48).contains(&name.len())
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{name}"
            );
        }
    }
}
