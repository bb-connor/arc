//! The disposition of a kernel failure.

use super::KernelError;
use crate::disposition::Disposition;

impl KernelError {
    /// How a loop, worker or endpoint handles this failure.
    ///
    /// Classification follows the variant and its typed cause, never the
    /// text. A variant whose cause is still text, or whose cause has no
    /// classification, is [`Disposition::Fatal`]. The match is exhaustive so
    /// a new variant must be classified before it compiles.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Admission(error) => error.disposition(),
            Self::ActiveResponse(error) => error.disposition(),
            Self::AdmissionRecovery(error) => error.disposition(),
            Self::ReceiptPersistence(error) => error.disposition(),
            Self::RevocationStore(error) => error.disposition(),
            Self::FindingDenied(denial) => denial.disposition(),
            Self::UntrustedInput(_)
            | Self::UnknownSession(_)
            | Self::SessionAlreadyExists(_)
            | Self::CapabilityExpired
            | Self::CapabilityNotYetValid
            | Self::CapabilityRevoked(_)
            | Self::InvalidSignature
            | Self::UntrustedIssuer
            | Self::CapabilityIssuanceDenied(_)
            | Self::OutOfScope { .. }
            | Self::OutOfScopeResource { .. }
            | Self::OutOfScopePrompt { .. }
            | Self::BudgetExhausted(_)
            | Self::CapturedBudgetReplay(_)
            | Self::DirectDispatchUnavailable
            | Self::SubjectMismatch { .. }
            | Self::DelegationChainRevoked(_)
            | Self::GovernedApprovalLifetimeExceeded
            | Self::DelegationInvalid(_)
            | Self::InvalidConstraint(_)
            | Self::ResponseDispatchRejected(_)
            | Self::GuardDenied(_)
            | Self::InvalidReceiptMetadata(_)
            | Self::ToolNotRegistered(_)
            | Self::ResourceNotRegistered(_)
            | Self::ResourceRootDenied { .. }
            | Self::PromptNotRegistered(_)
            | Self::SamplingNotAllowedByPolicy
            | Self::SamplingNotNegotiated
            | Self::SamplingContextNotSupported
            | Self::SamplingToolUseNotAllowedByPolicy
            | Self::SamplingToolUseNotNegotiated
            | Self::ElicitationNotAllowedByPolicy
            | Self::ElicitationNotNegotiated
            | Self::ElicitationFormNotSupported
            | Self::ElicitationUrlNotSupported
            | Self::UrlElicitationsRequired { .. }
            | Self::RootsNotNegotiated
            | Self::InvalidChildRequestParent
            | Self::RequestCancelled { .. }
            | Self::DpopVerificationFailed(_)
            | Self::ApprovalRejected(_)
            | Self::ReservingAuthorizationRejectsPresentedNonce => Disposition::Deny,
            Self::Overloaded { .. }
            | Self::HotPathDeadlineExceeded { .. }
            | Self::RuntimeAdmissionReadinessTimeout { .. }
            | Self::ExecutionNonceCapacity
            | Self::ReceiptWriterUnavailable(_) => Disposition::Retry,
            Self::DurableAdmissionRetained(_)
            | Self::SecurityDispatchOutcomeRecoveryRequired(_) => Disposition::Quarantine,
            Self::Clock(_)
            | Self::ReplayClockAnomaly { .. }
            | Self::FinancialBudgetExceeded { .. }
            | Self::SettlementConfiguration(_)
            | Self::SyncBridgeIncompatibleWithCurrentThreadRuntime
            | Self::FlowRuntimeUnavailable
            | Self::NoCrossCurrencyOracle { .. }
            | Self::CredentialReservationCleanup { .. } => Disposition::Fatal,
            // The cause is text, or carries both refusals and outages.
            Self::Session(_)
            | Self::CapabilityIssuanceFailed(_)
            | Self::RevocationSnapshotFuture
            | Self::RevocationSnapshotStale
            | Self::GovernedTransactionDenied(_)
            | Self::ActiveResponseNeverCommitted(_)
            | Self::ToolServerError(_)
            | Self::RequestIncomplete(_)
            | Self::ReceiptSigningFailed(_)
            | Self::ReceiptVerificationFailed(_)
            | Self::BudgetStore(_)
            | Self::DurableAdmission(_)
            | Self::CrossCurrencyOracle(_)
            | Self::Web3EvidenceUnavailable(_)
            | Self::ExecutionNonce(_)
            | Self::Internal(_)
            | Self::ApprovalReplay(_)
            | Self::Dpop(_) => Disposition::Fatal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_operation::AdmissionOperationStoreError;
    use crate::finding_denial::{FindingDenial, FindingDenialCode};

    #[test]
    fn refusals_deny_capacity_retries_and_text_causes_stay_fatal() {
        for (error, expected) in [
            (KernelError::CapabilityExpired, Disposition::Deny),
            (KernelError::GuardDenied("guard".into()), Disposition::Deny),
            (
                KernelError::OutOfScope {
                    tool: "t".into(),
                    server: "s".into(),
                },
                Disposition::Deny,
            ),
            (
                KernelError::Overloaded {
                    resource: super::super::OverloadResource::AdmissionKeys,
                },
                Disposition::Retry,
            ),
            (KernelError::ExecutionNonceCapacity, Disposition::Retry),
            (
                KernelError::SecurityDispatchOutcomeRecoveryRequired("reconcile".into()),
                Disposition::Quarantine,
            ),
            (
                KernelError::Clock(chio_security_types::clock::ClockError::Unavailable),
                Disposition::Fatal,
            ),
            (KernelError::Internal("text".into()), Disposition::Fatal),
            (
                KernelError::DurableAdmission("text".into()),
                Disposition::Fatal,
            ),
            (
                KernelError::GovernedTransactionDenied("text".into()),
                Disposition::Fatal,
            ),
        ] {
            assert_eq!(error.disposition(), expected, "{error:?}");
        }
    }

    #[test]
    fn typed_causes_classify_through_their_wrappers() {
        assert_eq!(
            KernelError::admission(AdmissionOperationStoreError::Unavailable("down".into()))
                .disposition(),
            Disposition::Retry
        );
        assert_eq!(
            KernelError::admission_refused("refused").disposition(),
            Disposition::Deny
        );
        assert_eq!(
            KernelError::admission(KernelError::CapabilityExpired).disposition(),
            Disposition::Deny
        );
        assert_eq!(
            KernelError::FindingDenied(FindingDenial::new(
                FindingDenialCode::Unavailable,
                "status feed",
            ))
            .disposition(),
            Disposition::Retry
        );
        assert_eq!(
            KernelError::FindingDenied(FindingDenial::new(
                FindingDenialCode::StatusDenied,
                "retracted",
            ))
            .disposition(),
            Disposition::Deny
        );
    }
}
