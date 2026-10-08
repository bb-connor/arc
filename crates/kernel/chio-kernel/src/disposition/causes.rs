//! Dispositions of the admission store, journal and record errors.
//!
//! A store that is unavailable, or a mutation whose outcome is not yet known,
//! is [`Disposition::Retry`]: the same work can succeed once the store
//! answers. A fenced owner, a broken invariant, the clock or missing
//! configuration is [`Disposition::Fatal`]. A record that does not match its
//! binding is [`Disposition::Quarantine`], and input that fails its contract
//! is [`Disposition::Deny`]. Every match is exhaustive so a new variant must
//! be classified before it compiles.

use super::Disposition;
use crate::admission_operation::{
    AdmissionCaptureError, AdmissionOperationError, AdmissionOperationStoreError,
    AdmissionRecoveryPortError, RemoteRecoveryFailureKind,
};
use crate::approval::ApprovalStoreError;
use crate::finding_denial::{FindingDenial, FindingDenialCode};
use crate::finding_pool::FindingPoolLedgerError;
use crate::payment::PaymentJournalError;
use crate::receipt_store::{
    AdmissionBudgetAuthorizationError, AdmissionPaymentJournalError, ReceiptStoreError,
};
use crate::revocation_store::RevocationStoreError;
use crate::supplemental_quota::SupplementalQuotaError;
use crate::tool_outcome::{ToolOutcomeError, ToolOutcomeStoreError};

impl AdmissionOperationError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Clock(_)
            | Self::UnsafeDurableAdmissionOff
            | Self::WrongOperation
            | Self::CoordinatorFenced
            | Self::InvalidStoreFence
            | Self::EmptyCommand
            | Self::DuplicateAttachment { .. }
            | Self::TerminalProjectionRequired
            | Self::MissingProjectionCapability { .. }
            | Self::MutationSequencerPoisoned
            | Self::FindingPoolLedgerAlreadyConfigured => Disposition::Fatal,
            Self::LeaseVersionMismatch | Self::LeaseExpired | Self::StaleVersion { .. } => {
                Disposition::Retry
            }
            Self::UntrustedInput(_)
            | Self::Empty { .. }
            | Self::TooLong { .. }
            | Self::ControlCharacter { .. }
            | Self::Padded { .. }
            | Self::InvalidDigest { .. }
            | Self::CanonicalJson(_)
            | Self::UnsafeInteger { .. }
            | Self::RequestNamespaceMismatch
            | Self::ReservedLocalSystemTenant => Disposition::Deny,
            Self::ZeroVersionOrEpoch
            | Self::VersionOverflow
            | Self::OperationIdMismatch
            | Self::StateKindMismatch { .. }
            | Self::DispatchStateMismatch
            | Self::TerminalReplayMismatch
            | Self::IllegalTransition { .. }
            | Self::AttachmentConflict { .. }
            | Self::AttachmentPhase { .. }
            | Self::ForbiddenAttachment { .. }
            | Self::ThresholdProposalMismatch
            | Self::ProviderAttemptBindingMismatch
            | Self::InvalidAuthorizationArtifactDigests
            | Self::CaptureDispositionMismatch
            | Self::CapturePreconditionMismatch
            | Self::CaptureBindingMismatch
            | Self::CaptureAuthorityMismatch
            | Self::CaptureCommitMismatch
            | Self::CaptureResponseDigestMismatch
            | Self::CaptureQuotaMismatch
            | Self::CaptureExpiryMismatch
            | Self::CaptureAuthorityTimeMismatch
            | Self::InvalidEconomicMutationBinding
            | Self::MissingParticipantAttachment { .. }
            | Self::InvalidParticipantRequirements
            | Self::RequestBindingMismatch
            | Self::TerminalProjectionBindingMismatch => Disposition::Quarantine,
        }
    }
}

impl AdmissionOperationStoreError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Unavailable(_) | Self::OutcomeUnknown(_) => Disposition::Retry,
            Self::Fenced | Self::Invariant(_) => Disposition::Fatal,
            Self::NotFound => Disposition::Quarantine,
            Self::Operation(error) => error.disposition(),
        }
    }
}

impl AdmissionRecoveryPortError {
    /// How a loop, worker or endpoint handles this failure. A local store
    /// error keeps its own classification.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Local(error) => error.disposition(),
            Self::Remote { kind, .. } => match kind {
                RemoteRecoveryFailureKind::Unavailable
                | RemoteRecoveryFailureKind::Conflict
                | RemoteRecoveryFailureKind::OutcomeUnknown => Disposition::Retry,
                RemoteRecoveryFailureKind::Fenced | RemoteRecoveryFailureKind::Invariant => {
                    Disposition::Fatal
                }
                RemoteRecoveryFailureKind::NotFound => Disposition::Quarantine,
            },
        }
    }
}

impl AdmissionCaptureError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Unavailable(_) | Self::OutcomeUnknown(_) => Disposition::Retry,
            Self::Fenced | Self::Invariant(_) => Disposition::Fatal,
            Self::Operation(error) => error.disposition(),
        }
    }
}

impl AdmissionBudgetAuthorizationError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Unavailable(_) | Self::OutcomeUnknown(_) => Disposition::Retry,
            Self::Fenced | Self::Invariant(_) => Disposition::Fatal,
            Self::Operation(error) => error.disposition(),
        }
    }
}

impl AdmissionPaymentJournalError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Unavailable(_) | Self::Conflict(_) | Self::OutcomeUnknown(_) => {
                Disposition::Retry
            }
            Self::Fenced | Self::Invariant(_) => Disposition::Fatal,
        }
    }
}

impl ApprovalStoreError {
    /// How a loop, worker or endpoint handles this failure. Only a storage
    /// backend fault is retried: every other failure is a decision the
    /// approval store made about this reservation or token.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Backend(_) => Disposition::Retry,
            Self::Clock(_) => Disposition::Fatal,
            Self::NotFound(_) | Self::Serialization(_) => Disposition::Quarantine,
            Self::UntrustedInput(_)
            | Self::Invalid(_)
            | Self::AlreadyResolved(_)
            | Self::Conflict(_)
            | Self::Replay(_) => Disposition::Deny,
        }
    }
}

impl FindingDenial {
    /// How a loop, worker or endpoint handles this denial. An unavailable
    /// seam retries; every other family refuses the finding.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self.code() {
            FindingDenialCode::Unavailable => Disposition::Retry,
            FindingDenialCode::CarrierInvalid
            | FindingDenialCode::AuthorityInvalid
            | FindingDenialCode::BindingMismatch
            | FindingDenialCode::StaleOrSuperseded
            | FindingDenialCode::StatusDenied
            | FindingDenialCode::QuotaExhausted => Disposition::Deny,
        }
    }
}

impl FindingPoolLedgerError {
    /// How a loop, worker or endpoint handles this failure. Ledger storage
    /// and receipt failures are text that cannot separate an outage from
    /// corruption, so they are fatal with the ledger's configuration faults.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::UntrustedInput(_)
            | Self::ReplayConflict
            | Self::AmountExceeded
            | Self::AllocationNotLive
            | Self::PoolBindingConflict
            | Self::LedgerDomainMismatch
            | Self::InvalidAllocationAuthority
            | Self::ReservationMissing
            | Self::ClaimDeadlineElapsed => Disposition::Deny,
            Self::TerminalConflict => Disposition::Quarantine,
            Self::Clock(_)
            | Self::LedgerDomainInUse
            | Self::LedgerStoreBindingMismatch
            | Self::InvalidLedgerStoreIdentity
            | Self::ReceiptSinkMismatch
            | Self::InvalidReceiptSink
            | Self::UnqualifiedRetentionArchive
            | Self::ReceiptAuthorityMismatch
            | Self::ReceiptConfigurationMismatch
            | Self::InvalidReceiptAuthority
            | Self::DurableAdmissionRequired
            | Self::AlreadyConfigured
            | Self::StartupAlreadyReconciled
            | Self::ReceiptAuthorityMissing
            | Self::ReceiptAuthorityAlreadyConfigured
            | Self::DurableReceiptStoreMissing
            | Self::Storage(_)
            | Self::Receipt(_)
            | Self::MutationReceiptFlushPoisoned => Disposition::Fatal,
        }
    }
}

impl PaymentJournalError {
    /// A payment journal record that fails validation cannot progress as
    /// stored.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        Disposition::Quarantine
    }
}

impl ReceiptStoreError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Pool(_) | Self::Timeout { .. } | Self::OutcomeUnknown(_) => Disposition::Retry,
            Self::Clock(_)
            | Self::Sqlite(_)
            | Self::Io(_)
            | Self::Unsupported(_)
            | Self::Fenced
            | Self::RetentionArchiveIncomplete { .. }
            | Self::RetentionWatermarkRegression { .. }
            | Self::ArchivedRangeProjection { .. }
            | Self::RetentionTenantScopeUnsupported
            | Self::WriterDead { .. } => Disposition::Fatal,
            Self::InvalidOutcome(_) | Self::ReadBoundary(_) | Self::ReadAuthorization(_) => {
                Disposition::Deny
            }
            Self::UntrustedInput(_)
            | Self::Json(_)
            | Self::CryptoDecode(_)
            | Self::Canonical(_)
            | Self::Conflict(_)
            | Self::NotFound(_) => Disposition::Quarantine,
        }
    }
}

impl RevocationStoreError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::OutcomeUnknown(_) => Disposition::Retry,
            Self::Clock(_)
            | Self::Sqlite(_)
            | Self::Io(_)
            | Self::Sync(_)
            | Self::Fenced { .. } => Disposition::Fatal,
        }
    }
}

impl SupplementalQuotaError {
    /// How a loop, worker or endpoint handles this failure. Only a missing
    /// verifier is configuration; every other failure refuses the artifact.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::MissingVerifier => Disposition::Fatal,
            Self::Canonicalization(_) => Disposition::Quarantine,
            Self::EmptyAuthorization
            | Self::UnknownProfile(_)
            | Self::ProfileNotNegotiated(_)
            | Self::VerifierRejected(_)
            | Self::EmptyContextField(_)
            | Self::ContextMismatch(_)
            | Self::ArtifactDigestMismatch
            | Self::RequestBindingMismatch
            | Self::EmptyClaimField(_)
            | Self::LimitExceeded { .. }
            | Self::InvalidSha256Digest(_)
            | Self::InvalidNegotiatedFeatures(_)
            | Self::Expired { .. }
            | Self::EmptyRevocationId
            | Self::EmptyRevocationSet
            | Self::DuplicateRevocationId(_)
            | Self::EmptySupplementalRevocationIds
            | Self::RevocationIdsNotCanonical
            | Self::RevocationDigestMismatch
            | Self::RevocationSetMismatch => Disposition::Deny,
        }
    }
}

impl ToolOutcomeError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Clock(_) => Disposition::Fatal,
            Self::ReleaseAuthorityUnavailable(_) | Self::Cas { .. } => Disposition::Retry,
            Self::UntrustedInput(_) | Self::Invalid(_) | Self::TooLarge { .. } => Disposition::Deny,
            Self::Canonical(_) | Self::Binding(_) | Self::Transition { .. } | Self::Overflow(_) => {
                Disposition::Quarantine
            }
        }
    }
}

impl ToolOutcomeStoreError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Unavailable(_) | Self::CasConflict => Disposition::Retry,
            Self::Fenced | Self::Invariant(_) => Disposition::Fatal,
            Self::NotFound | Self::Conflict | Self::Compacted { .. } => Disposition::Quarantine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_operation::AdmissionOperationState;
    use chio_security_types::clock::ClockError;

    #[test]
    fn operation_errors_separate_input_records_races_and_shared_faults() {
        for (error, expected) in [
            (
                AdmissionOperationError::Clock(ClockError::Unavailable),
                Disposition::Fatal,
            ),
            (
                AdmissionOperationError::CoordinatorFenced,
                Disposition::Fatal,
            ),
            (
                AdmissionOperationError::MutationSequencerPoisoned,
                Disposition::Fatal,
            ),
            (
                AdmissionOperationError::StaleVersion {
                    expected: 2,
                    actual: 3,
                },
                Disposition::Retry,
            ),
            (AdmissionOperationError::LeaseExpired, Disposition::Retry),
            (
                AdmissionOperationError::Empty {
                    field: "request_id",
                },
                Disposition::Deny,
            ),
            (
                AdmissionOperationError::ReservedLocalSystemTenant,
                Disposition::Deny,
            ),
            (
                AdmissionOperationError::IllegalTransition {
                    from: AdmissionOperationState::Completed,
                    to: AdmissionOperationState::Prepared,
                },
                Disposition::Quarantine,
            ),
            (
                AdmissionOperationError::ProviderAttemptBindingMismatch,
                Disposition::Quarantine,
            ),
        ] {
            assert_eq!(error.disposition(), expected, "{error:?}");
        }
    }

    #[test]
    fn store_unavailability_retries_and_fencing_is_fatal() {
        assert_eq!(
            AdmissionOperationStoreError::Unavailable("down".into()).disposition(),
            Disposition::Retry
        );
        assert_eq!(
            AdmissionOperationStoreError::OutcomeUnknown("timeout".into()).disposition(),
            Disposition::Retry
        );
        assert_eq!(
            AdmissionOperationStoreError::Fenced.disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            AdmissionOperationStoreError::Invariant("page".into()).disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            AdmissionOperationStoreError::NotFound.disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            AdmissionOperationStoreError::Operation(AdmissionOperationError::LeaseExpired)
                .disposition(),
            Disposition::Retry
        );
        assert_eq!(
            AdmissionCaptureError::Unavailable("down".into()).disposition(),
            Disposition::Retry
        );
        assert_eq!(
            AdmissionCaptureError::Fenced.disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            AdmissionBudgetAuthorizationError::Invariant("hold".into()).disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            AdmissionBudgetAuthorizationError::Operation(
                AdmissionOperationError::CaptureBindingMismatch
            )
            .disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            AdmissionPaymentJournalError::Conflict("cas".into()).disposition(),
            Disposition::Retry
        );
        assert_eq!(
            AdmissionPaymentJournalError::Fenced.disposition(),
            Disposition::Fatal
        );
    }

    #[test]
    fn recovery_ports_and_supplemental_quota_classify_by_variant() {
        assert_eq!(
            AdmissionRecoveryPortError::Local(AdmissionOperationStoreError::Unavailable(
                "down".into()
            ))
            .disposition(),
            Disposition::Retry
        );
        assert_eq!(
            AdmissionRecoveryPortError::remote(RemoteRecoveryFailureKind::Fenced, std::fmt::Error)
                .disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            AdmissionRecoveryPortError::remote(
                RemoteRecoveryFailureKind::NotFound,
                std::fmt::Error
            )
            .disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            SupplementalQuotaError::MissingVerifier.disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            SupplementalQuotaError::RevocationSetMismatch.disposition(),
            Disposition::Deny
        );
        assert_eq!(
            SupplementalQuotaError::Expired {
                expires_at: 1,
                now: 2
            }
            .disposition(),
            Disposition::Deny
        );
    }

    #[test]
    fn only_an_approval_backend_fault_retries() {
        assert_eq!(
            ApprovalStoreError::Backend("down".into()).disposition(),
            Disposition::Retry
        );
        for decided in [
            ApprovalStoreError::Invalid("set".into()),
            ApprovalStoreError::AlreadyResolved("id".into()),
            ApprovalStoreError::Conflict("state".into()),
            ApprovalStoreError::Replay("token".into()),
        ] {
            assert_eq!(decided.disposition(), Disposition::Deny, "{decided:?}");
        }
        assert_eq!(
            ApprovalStoreError::NotFound("id".into()).disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            ApprovalStoreError::Clock(ClockError::Unavailable).disposition(),
            Disposition::Fatal
        );
    }

    #[test]
    fn finding_pool_refusals_deny_and_ledger_faults_are_fatal() {
        assert_eq!(
            FindingPoolLedgerError::AmountExceeded.disposition(),
            Disposition::Deny
        );
        assert_eq!(
            FindingPoolLedgerError::ClaimDeadlineElapsed.disposition(),
            Disposition::Deny
        );
        assert_eq!(
            FindingPoolLedgerError::TerminalConflict.disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            FindingPoolLedgerError::Storage("disk".into()).disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            FindingPoolLedgerError::ReceiptAuthorityMissing.disposition(),
            Disposition::Fatal
        );
    }

    #[test]
    fn receipt_revocation_and_outcome_stores_classify_by_variant() {
        assert_eq!(
            ReceiptStoreError::Pool("exhausted".into()).disposition(),
            Disposition::Retry
        );
        assert_eq!(ReceiptStoreError::Fenced.disposition(), Disposition::Fatal);
        assert_eq!(
            ReceiptStoreError::Unsupported("ranges".into()).disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            ReceiptStoreError::Conflict("receipt".into()).disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            ReceiptStoreError::InvalidOutcome("filter".into()).disposition(),
            Disposition::Deny
        );
        assert_eq!(
            RevocationStoreError::OutcomeUnknown("commit".into()).disposition(),
            Disposition::Retry
        );
        assert_eq!(
            RevocationStoreError::Sync("lock".into()).disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            ToolOutcomeError::ReleaseAuthorityUnavailable("outcome store").disposition(),
            Disposition::Retry
        );
        assert_eq!(
            ToolOutcomeError::Binding("operation").disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            ToolOutcomeError::Invalid("output").disposition(),
            Disposition::Deny
        );
        assert_eq!(
            ToolOutcomeStoreError::CasConflict.disposition(),
            Disposition::Retry
        );
        assert_eq!(
            ToolOutcomeStoreError::Invariant("row".into()).disposition(),
            Disposition::Fatal
        );
        assert_eq!(
            ToolOutcomeStoreError::NotFound.disposition(),
            Disposition::Quarantine
        );
    }
}
