//! Registered response rejection reasons shared by scheduler evidence and logs.
use crate::{CanonicalFailure, ExecutorError, PlanDefect, RecordDefect, StateMachineError};

impl CanonicalFailure {
    /// Registered, input-independent reason retained in evidence and diagnostics.
    pub fn code(&self) -> &str {
        match self {
            Self::Encoding(..) => "urn:chio:error:kernel:response-canonical-encoding",
            Self::Body(..) => "urn:chio:error:kernel:response-canonical-body",
            Self::Identifier(..) => "urn:chio:error:kernel:response-canonical-identifier",
            Self::Value(..) => "urn:chio:error:kernel:response-canonical-value",
            Self::Receipt(..) => "urn:chio:error:kernel:response-canonical-receipt",
        }
    }
}

impl PlanDefect {
    /// Registered, input-independent reason retained in evidence and diagnostics.
    pub fn code(&self) -> &str {
        match self {
            Self::NoEffects => "urn:chio:error:kernel:response-plan-no-effects",
            Self::TooManyEffects { .. } => "urn:chio:error:kernel:response-plan-too-many-effects",
            Self::ZeroTtl => "urn:chio:error:kernel:response-plan-zero-ttl",
            Self::ExpiryOverflow => "urn:chio:error:kernel:response-plan-expiry-overflow",
            Self::AffectedIds(..) => "urn:chio:error:kernel:response-plan-affected-ids",
            Self::AffectedSetHash(..) => "urn:chio:error:kernel:response-plan-affected-set-hash",
            Self::AffectedSetHashMismatch => {
                "urn:chio:error:kernel:response-plan-affected-set-hash-mismatch"
            }
            Self::EffectOrdinalOverflow(..) => {
                "urn:chio:error:kernel:response-plan-effect-ordinal-overflow"
            }
            Self::EffectBound(..) => "urn:chio:error:kernel:response-plan-effect-bound",
            Self::ContributionNotJson(..) => {
                "urn:chio:error:kernel:response-plan-contribution-not-json"
            }
            Self::ContributionNotCanonical => {
                "urn:chio:error:kernel:response-plan-contribution-not-canonical"
            }
            Self::ContributionHashMismatch => {
                "urn:chio:error:kernel:response-plan-contribution-hash-mismatch"
            }
            Self::EffectIdMismatch => "urn:chio:error:kernel:response-plan-effect-id-mismatch",
            Self::FreezeContribution(..) => {
                "urn:chio:error:kernel:response-plan-freeze-contribution"
            }
            Self::FreezeTargetNotLineage => {
                "urn:chio:error:kernel:response-plan-freeze-target-not-lineage"
            }
            Self::FreezeAcquisitionNotExact => {
                "urn:chio:error:kernel:response-plan-freeze-acquisition-not-exact"
            }
            Self::FreezeBindingMismatch(..) => {
                "urn:chio:error:kernel:response-plan-freeze-binding-mismatch"
            }
            Self::PlanBodyHash(..) => "urn:chio:error:kernel:response-plan-plan-body-hash",
            Self::PlanBodyHashEncoding(..) => {
                "urn:chio:error:kernel:response-plan-plan-body-hash-encoding"
            }
            Self::PlanHashMismatch => "urn:chio:error:kernel:response-plan-plan-hash-mismatch",
        }
    }
}

impl RecordDefect {
    /// Registered, input-independent reason retained in evidence and diagnostics.
    pub fn code(&self) -> &str {
        match self {
            Self::Decode(..) => "urn:chio:error:kernel:response-record-decode",
            Self::NotCanonical => "urn:chio:error:kernel:response-record-not-canonical",
            Self::BodyHashMismatch => "urn:chio:error:kernel:response-record-body-hash-mismatch",
            Self::TenantMismatch => "urn:chio:error:kernel:response-record-tenant-mismatch",
            Self::ActionMismatch => "urn:chio:error:kernel:response-record-action-mismatch",
            Self::GenerationMismatch => "urn:chio:error:kernel:response-record-generation-mismatch",
            Self::StateMismatch => "urn:chio:error:kernel:response-record-state-mismatch",
            Self::DueAtMismatch => "urn:chio:error:kernel:response-record-due-at-mismatch",
            Self::Lifecycle(..) => "urn:chio:error:kernel:response-record-lifecycle",
            Self::EmptyMutationLog => "urn:chio:error:kernel:response-record-empty-mutation-log",
            Self::ZeroMutationGeneration => {
                "urn:chio:error:kernel:response-record-zero-mutation-generation"
            }
            Self::MissingApplyingLease => {
                "urn:chio:error:kernel:response-record-missing-applying-lease"
            }
        }
    }
}

impl StateMachineError {
    /// Registered, input-independent reason retained in evidence and diagnostics.
    pub fn code(&self) -> &str {
        match self {
            Self::Canonical(inner) => inner.code(),
            Self::IncompleteApplication => {
                "urn:chio:error:kernel:response-state-incomplete-application"
            }
            Self::InvalidEffectLifecycle => {
                "urn:chio:error:kernel:response-state-invalid-effect-lifecycle"
            }
            Self::InvalidFailureRecord => {
                "urn:chio:error:kernel:response-state-invalid-failure-record"
            }
            Self::InvalidPlan(inner) => inner.code(),
            Self::InvalidDispatch(inner) => inner.code(),
            Self::InvalidRecord(inner) => inner.code(),
            Self::InvalidTiming => "urn:chio:error:kernel:response-state-invalid-timing",
            Self::InvalidTransition => "urn:chio:error:kernel:response-state-invalid-transition",
            Self::MutationLimit(..) => "urn:chio:error:kernel:response-state-mutation-limit",
            Self::NotDue => "urn:chio:error:kernel:response-state-not-due",
            Self::GenerationOverflow => "urn:chio:error:kernel:response-state-generation-overflow",
            Self::StaleGeneration => "urn:chio:error:kernel:response-state-stale-generation",
            Self::UnknownEffect => "urn:chio:error:kernel:response-state-unknown-effect",
            Self::UnrestoredEffects => "urn:chio:error:kernel:response-state-unrestored-effects",
            Self::Shape(..) => "urn:chio:error:kernel:response-state-shape",
            Self::Store(inner) => inner.code().as_str(),
        }
    }
}

impl ExecutorError {
    /// Registered, input-independent reason retained in evidence and diagnostics.
    pub fn code(&self) -> &str {
        match self {
            Self::ApprovalRequired => "urn:chio:error:kernel:response-executor-approval-required",
            Self::AttemptOverflow => "urn:chio:error:kernel:response-executor-attempt-overflow",
            Self::Alert(inner) => inner.code().as_str(),
            Self::Canonical(inner) => inner.code(),
            Self::EffectOutcomeUnknown => {
                "urn:chio:error:kernel:response-executor-effect-outcome-unknown"
            }
            Self::EffectMutation(inner) => inner.code().as_str(),
            Self::EffectQuery(inner) => inner.code().as_str(),
            Self::InvalidEffectResult => {
                "urn:chio:error:kernel:response-executor-invalid-effect-result"
            }
            Self::GenerationOverflow => {
                "urn:chio:error:kernel:response-executor-generation-overflow"
            }
            Self::GenerationWidth(..) => "urn:chio:error:kernel:response-executor-generation-width",
            Self::InvalidEffectJournal => {
                "urn:chio:error:kernel:response-executor-invalid-effect-journal"
            }
            Self::EffectJournalDecode(..) => {
                "urn:chio:error:kernel:response-executor-effect-journal-decode"
            }
            Self::EffectJournalEncoding(..) => {
                "urn:chio:error:kernel:response-executor-effect-journal-encoding"
            }
            Self::InvalidActiveEvidence => {
                "urn:chio:error:kernel:response-executor-invalid-active-evidence"
            }
            Self::ActiveEvidenceMutationBound(..) => {
                "urn:chio:error:kernel:response-executor-active-evidence-mutation-bound"
            }
            Self::ActiveEvidenceEncoding(..) => {
                "urn:chio:error:kernel:response-executor-active-evidence-encoding"
            }
            Self::ActiveEvidenceBinding(..) => {
                "urn:chio:error:kernel:response-executor-active-evidence-binding"
            }
            Self::Receipt(inner) => inner.code().as_str(),
            Self::ReceiptLineageMismatch => {
                "urn:chio:error:kernel:response-executor-receipt-lineage-mismatch"
            }
            Self::StaleLease => "urn:chio:error:kernel:response-executor-stale-lease",
            Self::Store(inner) => inner.code().as_str(),
            Self::StateMachine(inner) => inner.code(),
            Self::WorkMismatch => "urn:chio:error:kernel:response-executor-work-mismatch",
        }
    }
}
