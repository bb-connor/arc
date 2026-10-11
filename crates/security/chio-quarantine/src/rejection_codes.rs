//! Registered executor rejection reasons.
use crate::ExecutorError;

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
