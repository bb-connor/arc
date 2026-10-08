//! Why a durable admission refused or failed.
//!
//! Each variant renders exactly the reason durable admission reports, and
//! [`KernelError::Admission`] prefixes it with "durable admission failed: "
//! like every other durable admission failure, so the report text and code
//! do not depend on the variant. Typed causes stay reachable through
//! [`std::error::Error::source`]. [`DurableAdmissionError::disposition`]
//! classifies by variant, never by text.

use std::borrow::Cow;

use super::KernelError;
use crate::admission_operation::{
    AdmissionCaptureError, AdmissionOperationError, AdmissionOperationState,
    AdmissionOperationStoreError,
};
use crate::disposition::Disposition;
use crate::payment::PaymentJournalError;
use crate::receipt_store::{
    AdmissionBudgetAuthorizationError, AdmissionPaymentJournalError, ReceiptStoreError,
};
use crate::revocation_store::RevocationStoreError;
use crate::supplemental_quota::SupplementalQuotaError;
use crate::tool_outcome::{ToolOutcomeError, ToolOutcomeStoreError};

/// The reason text of an admission failure: fixed, or naming the retained
/// state or record it refers to.
pub type AdmissionReason = Cow<'static, str>;

/// A durable admission refusal or failure with its typed cause.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DurableAdmissionError {
    /// Admission refuses the request or its authority. The service is
    /// healthy, and the same request is refused again.
    #[error("{0}")]
    Refused(AdmissionReason),
    /// The request conflicts with an operation already retained for its
    /// request id.
    #[error("{0}")]
    Conflict(AdmissionReason),
    /// Another owner or background recovery holds the operation. The same
    /// request can succeed once that work settles.
    #[error("{0}")]
    Pending(AdmissionReason),
    /// The operation is in a state this step cannot run from.
    #[error("{reason}")]
    State {
        state: AdmissionOperationState,
        reason: AdmissionReason,
    },
    /// A retained record or a participant's answer does not match the
    /// operation it belongs to.
    #[error("{0}")]
    Record(AdmissionReason),
    /// An invariant shared by every operation failed: a store contract, a
    /// counter or a lock.
    #[error("{0}")]
    Invariant(AdmissionReason),
    /// The kernel lacks a store, adapter or capability the admission needs.
    #[error("{0}")]
    Unsupported(&'static str),
    /// A participant callback panicked, so the step it ran is unconfirmed.
    #[error("{0}")]
    Panicked(&'static str),
    #[error("{0}")]
    Operation(#[from] AdmissionOperationError),
    #[error("{0}")]
    Store(#[from] AdmissionOperationStoreError),
    #[error("{0}")]
    Capture(#[from] AdmissionCaptureError),
    #[error("{0}")]
    BudgetAuthorization(#[from] AdmissionBudgetAuthorizationError),
    #[error("{0}")]
    PaymentJournal(#[from] AdmissionPaymentJournalError),
    #[error("{0}")]
    PaymentRecord(#[from] PaymentJournalError),
    #[error("{0}")]
    Receipts(#[from] ReceiptStoreError),
    #[error("{0}")]
    Revocation(#[from] RevocationStoreError),
    #[error("{0}")]
    ToolOutcome(#[from] ToolOutcomeError),
    #[error("{0}")]
    OutcomeStore(#[from] ToolOutcomeStoreError),
    #[error("{0}")]
    Supplemental(#[from] SupplementalQuotaError),
    /// Canonical encoding of a request or record value failed.
    #[error("{0}")]
    Encoding(#[from] chio_core::Error),
    /// Encoding a record as JSON failed.
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// A kernel step the admission depends on failed.
    #[error("{0}")]
    Kernel(#[source] Box<KernelError>),
    /// A cause with no classification of its own.
    #[error("{0}")]
    Dependency(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// `context` names the step that failed with `source`.
    #[error("{context}: {source}")]
    Context {
        context: &'static str,
        #[source]
        source: Box<DurableAdmissionError>,
    },
}

impl DurableAdmissionError {
    /// Wrap a cause that has no variant of its own. It classifies as fatal.
    pub fn dependency(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Dependency(Box::new(source))
    }

    /// Name the step that failed; renders as "{context}: {self}".
    #[must_use]
    pub fn context(self, context: &'static str) -> Self {
        Self::Context {
            context,
            source: Box::new(self),
        }
    }

    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Refused(_) | Self::Conflict(_) => Disposition::Deny,
            Self::Pending(_) => Disposition::Retry,
            Self::State { .. } | Self::Record(_) | Self::Encoding(_) | Self::Json(_) => {
                Disposition::Quarantine
            }
            Self::Invariant(_)
            | Self::Unsupported(_)
            | Self::Panicked(_)
            | Self::Dependency(_) => Disposition::Fatal,
            Self::Operation(error) => error.disposition(),
            Self::Store(error) => error.disposition(),
            Self::Capture(error) => error.disposition(),
            Self::BudgetAuthorization(error) => error.disposition(),
            Self::PaymentJournal(error) => error.disposition(),
            Self::PaymentRecord(error) => error.disposition(),
            Self::Receipts(error) => error.disposition(),
            Self::Revocation(error) => error.disposition(),
            Self::ToolOutcome(error) => error.disposition(),
            Self::OutcomeStore(error) => error.disposition(),
            Self::Supplemental(error) => error.disposition(),
            Self::Kernel(error) => error.disposition(),
            Self::Context { source, .. } => source.disposition(),
        }
    }

    /// The failure under any step names added by [`Self::context`].
    #[must_use]
    pub fn root(&self) -> &Self {
        match self {
            Self::Context { source, .. } => source.root(),
            error => error,
        }
    }
}

impl From<KernelError> for DurableAdmissionError {
    fn from(error: KernelError) -> Self {
        Self::Kernel(Box::new(error))
    }
}

impl From<DurableAdmissionError> for KernelError {
    fn from(error: DurableAdmissionError) -> Self {
        Self::Admission(Box::new(error))
    }
}

impl KernelError {
    /// A durable admission failure with a typed cause.
    pub fn admission(cause: impl Into<DurableAdmissionError>) -> Self {
        Self::from(cause.into())
    }

    /// A durable admission failure in the step named by `context`.
    pub fn admission_in(context: &'static str, cause: impl Into<DurableAdmissionError>) -> Self {
        Self::from(cause.into().context(context))
    }

    pub fn admission_refused(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(DurableAdmissionError::Refused(reason.into()))
    }

    pub fn admission_conflict(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(DurableAdmissionError::Conflict(reason.into()))
    }

    pub fn admission_pending(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(DurableAdmissionError::Pending(reason.into()))
    }

    pub fn admission_state(
        state: AdmissionOperationState,
        reason: impl Into<AdmissionReason>,
    ) -> Self {
        Self::from(DurableAdmissionError::State {
            state,
            reason: reason.into(),
        })
    }

    pub fn admission_record(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(DurableAdmissionError::Record(reason.into()))
    }

    pub fn admission_invariant(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(DurableAdmissionError::Invariant(reason.into()))
    }

    pub fn admission_unsupported(reason: &'static str) -> Self {
        Self::from(DurableAdmissionError::Unsupported(reason))
    }

    pub fn admission_panicked(reason: &'static str) -> Self {
        Self::from(DurableAdmissionError::Panicked(reason))
    }

    /// The typed durable admission failure this error carries, if any.
    #[must_use]
    pub fn durable_admission(&self) -> Option<&DurableAdmissionError> {
        match self {
            Self::Admission(error) => Some(&**error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    /// Each typed failure must read exactly as the untyped one it replaces,
    /// in both its text and its structured report.
    fn assert_reads_as_untyped(typed: KernelError, reason: &str) {
        let untyped = KernelError::DurableAdmission(reason.to_owned());
        assert_eq!(typed.to_string(), untyped.to_string());
        assert_eq!(typed.report(), untyped.report());
    }

    #[test]
    fn typed_failures_keep_the_untyped_text_and_report() {
        assert_reads_as_untyped(
            KernelError::admission_refused("matching grants disagree"),
            "matching grants disagree",
        );
        assert_reads_as_untyped(
            KernelError::admission_conflict(format!("request id conflicts with {}", "op-1")),
            "request id conflicts with op-1",
        );
        assert_reads_as_untyped(
            KernelError::admission_state(
                AdmissionOperationState::Completed,
                "capture cannot start from state Completed",
            ),
            "capture cannot start from state Completed",
        );
        let store = AdmissionOperationStoreError::Unavailable("db closed".into());
        let reason = store.to_string();
        assert_reads_as_untyped(KernelError::admission(store), &reason);
        let journal = AdmissionPaymentJournalError::Fenced;
        let reason = format!("payment journal load failed: {journal}");
        assert_reads_as_untyped(
            KernelError::admission_in("payment journal load failed", journal),
            &reason,
        );
    }

    #[test]
    fn typed_causes_stay_reachable_as_sources() {
        let error = KernelError::admission_in(
            "pre-dispatch release failed",
            AdmissionOperationStoreError::Fenced,
        );
        assert!(matches!(
            error.durable_admission().map(DurableAdmissionError::root),
            Some(DurableAdmissionError::Store(
                AdmissionOperationStoreError::Fenced
            ))
        ));
        let mut cause = error.source();
        let mut found = false;
        while let Some(source) = cause {
            found |= source
                .downcast_ref::<AdmissionOperationStoreError>()
                .is_some();
            cause = source.source();
        }
        assert!(found, "the store error must remain in the source chain");
    }

    #[test]
    fn each_category_has_one_disposition() {
        for (error, expected) in [
            (
                DurableAdmissionError::Refused("r".into()),
                Disposition::Deny,
            ),
            (
                DurableAdmissionError::Conflict("c".into()),
                Disposition::Deny,
            ),
            (
                DurableAdmissionError::Pending("p".into()),
                Disposition::Retry,
            ),
            (
                DurableAdmissionError::State {
                    state: AdmissionOperationState::Completed,
                    reason: "s".into(),
                },
                Disposition::Quarantine,
            ),
            (
                DurableAdmissionError::Record("r".into()),
                Disposition::Quarantine,
            ),
            (
                DurableAdmissionError::Invariant("i".into()),
                Disposition::Fatal,
            ),
            (DurableAdmissionError::Unsupported("u"), Disposition::Fatal),
            (DurableAdmissionError::Panicked("p"), Disposition::Fatal),
            (
                DurableAdmissionError::dependency(std::fmt::Error),
                Disposition::Fatal,
            ),
            (
                DurableAdmissionError::Store(AdmissionOperationStoreError::Unavailable(
                    "down".into(),
                )),
                Disposition::Retry,
            ),
            (
                DurableAdmissionError::Store(AdmissionOperationStoreError::Fenced).context("step"),
                Disposition::Fatal,
            ),
            (
                DurableAdmissionError::Pending("p".into()).context("step"),
                Disposition::Retry,
            ),
        ] {
            assert_eq!(error.disposition(), expected, "{error:?}");
        }
    }

    #[test]
    fn only_the_typed_variant_exposes_a_durable_admission_cause() {
        assert!(matches!(
            KernelError::admission_pending("owner").durable_admission(),
            Some(DurableAdmissionError::Pending(reason)) if reason == "owner"
        ));
        assert!(KernelError::DurableAdmission("owner".into())
            .durable_admission()
            .is_none());
    }
}
