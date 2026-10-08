//! Why a governed active-response operation, its cleanup or its terminal
//! receipt outbox failed.
//!
//! [`KernelError::ActiveResponse`] renders these as "internal error: {reason}"
//! with the internal report code, exactly as the untyped internal variant
//! does, so receipts and wire errors do not depend on the variant.
//! [`ActiveResponseError::disposition`] classifies by variant, never by text.

use super::{AdmissionReason, KernelError};
use crate::disposition::Disposition;
use crate::security_admission_operation::AdmissionOperationError as SecurityAdmissionOperationError;

/// A governed active-response failure with its typed cause.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActiveResponseError {
    /// The operation belongs to another executor or coordinator authority.
    /// The service is healthy and this kernel refuses it again.
    #[error("{0}")]
    Refused(AdmissionReason),
    /// Cleanup or terminal receipt work for the operation has not finished.
    #[error("{0}")]
    Pending(AdmissionReason),
    /// A pass left work unfinished. `first` is the first item failure, and
    /// `reason` already reports it.
    #[error("{reason}")]
    Unfinished {
        reason: AdmissionReason,
        #[source]
        first: Box<KernelError>,
    },
    /// The operation's anchor, cleanup action, approval reservation or
    /// receipt outbox no longer matches it, or the operation is in a state
    /// the step cannot run from.
    #[error("{0}")]
    Record(AdmissionReason),
    /// An invariant shared by every operation failed: a store page, a
    /// counter or a commit contract.
    #[error("{0}")]
    Invariant(AdmissionReason),
    /// A store or authority the step needs is not installed.
    #[error("{0}")]
    Unsupported(&'static str),
    /// The security admission operation store failed.
    #[error("security admission operation failed: {0}")]
    Operation(#[source] SecurityAdmissionOperationError),
    /// The security admission operation store refused a request or binding
    /// already owned by another operation.
    #[error("security admission operation conflicted: {0}")]
    OperationConflict(String),
    /// A cause with no classification of its own.
    #[error("{0}")]
    Dependency(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// `context` names the step that failed with `source`.
    #[error("{context}: {source}")]
    Context {
        context: &'static str,
        #[source]
        source: Box<ActiveResponseError>,
    },
}

impl ActiveResponseError {
    /// How a loop, worker or endpoint handles this failure.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Refused(_) | Self::OperationConflict(_) => Disposition::Deny,
            Self::Operation(error) => error.disposition(),
            Self::Pending(_) | Self::Unfinished { .. } => Disposition::Retry,
            Self::Record(_) => Disposition::Quarantine,
            Self::Invariant(_) | Self::Unsupported(_) | Self::Dependency(_) => Disposition::Fatal,
            Self::Context { source, .. } => source.disposition(),
        }
    }

    /// The failure under any step names added as context.
    #[must_use]
    pub fn root(&self) -> &Self {
        match self {
            Self::Context { source, .. } => source.root(),
            error => error,
        }
    }
}

impl From<SecurityAdmissionOperationError> for ActiveResponseError {
    fn from(error: SecurityAdmissionOperationError) -> Self {
        match error {
            SecurityAdmissionOperationError::Conflict(reason) => Self::OperationConflict(reason),
            error => Self::Operation(error),
        }
    }
}

impl From<ActiveResponseError> for KernelError {
    fn from(error: ActiveResponseError) -> Self {
        Self::ActiveResponse(Box::new(error))
    }
}

impl KernelError {
    pub fn active_response_refused(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(ActiveResponseError::Refused(reason.into()))
    }

    pub fn active_response_pending(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(ActiveResponseError::Pending(reason.into()))
    }

    /// Work remains after a pass. `reason` must already report `first`.
    pub fn active_response_unfinished(reason: impl Into<AdmissionReason>, first: Self) -> Self {
        Self::from(ActiveResponseError::Unfinished {
            reason: reason.into(),
            first: Box::new(first),
        })
    }

    pub fn active_response_record(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(ActiveResponseError::Record(reason.into()))
    }

    pub fn active_response_invariant(reason: impl Into<AdmissionReason>) -> Self {
        Self::from(ActiveResponseError::Invariant(reason.into()))
    }

    pub fn active_response_unsupported(reason: &'static str) -> Self {
        Self::from(ActiveResponseError::Unsupported(reason))
    }

    /// An active-response step named by `context` failed with `source`.
    pub fn active_response_in(
        context: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::from(ActiveResponseError::Context {
            context,
            source: Box::new(ActiveResponseError::Dependency(Box::new(source))),
        })
    }

    /// The typed active-response failure this error carries, if any.
    #[must_use]
    pub fn active_response_failure(&self) -> Option<&ActiveResponseError> {
        match self {
            Self::ActiveResponse(error) => Some(&**error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_reads_as_internal(typed: KernelError, reason: &str) {
        let untyped = KernelError::Internal(reason.to_owned());
        assert_eq!(typed.to_string(), untyped.to_string());
        assert_eq!(typed.report(), untyped.report());
    }

    #[test]
    fn typed_failures_keep_the_internal_text_and_report() {
        assert_reads_as_internal(
            KernelError::active_response_refused("belongs to a different executor authority"),
            "belongs to a different executor authority",
        );
        assert_reads_as_internal(
            KernelError::active_response_record(format!("operation {} disappeared", "op-1")),
            "operation op-1 disappeared",
        );
        let first = KernelError::active_response_refused("foreign");
        let reason = format!("work remains: {first}");
        assert_reads_as_internal(
            KernelError::active_response_unfinished(reason.clone(), first),
            &reason,
        );
        assert_reads_as_internal(
            KernelError::active_response_in("approval lookup failed", std::fmt::Error),
            &format!("approval lookup failed: {}", std::fmt::Error),
        );
    }

    #[test]
    fn security_operation_errors_convert_to_typed_causes_with_unchanged_text() {
        let failed = SecurityAdmissionOperationError::Unavailable("store down".into());
        let reason = format!("security admission operation failed: {failed}");
        let converted = KernelError::from(failed);
        assert!(matches!(
            converted.active_response_failure(),
            Some(ActiveResponseError::Operation(
                SecurityAdmissionOperationError::Unavailable(detail)
            )) if detail == "store down"
        ));
        assert_eq!(converted.disposition(), Disposition::Retry);
        assert_reads_as_internal(converted, &reason);

        let conflicted = KernelError::from(SecurityAdmissionOperationError::Conflict(
            "request_id is owned".into(),
        ));
        assert!(matches!(
            conflicted.active_response_failure(),
            Some(ActiveResponseError::OperationConflict(reason)) if reason == "request_id is owned"
        ));
        assert_eq!(conflicted.disposition(), Disposition::Deny);
        assert_reads_as_internal(
            conflicted,
            "security admission operation conflicted: request_id is owned",
        );
    }

    #[test]
    fn each_category_has_one_disposition() {
        for (error, expected) in [
            (KernelError::active_response_refused("r"), Disposition::Deny),
            (
                KernelError::active_response_pending("p"),
                Disposition::Retry,
            ),
            (
                KernelError::active_response_unfinished(
                    "u",
                    KernelError::active_response_refused("r"),
                ),
                Disposition::Retry,
            ),
            (
                KernelError::active_response_record("r"),
                Disposition::Quarantine,
            ),
            (
                KernelError::active_response_invariant("i"),
                Disposition::Fatal,
            ),
            (
                KernelError::active_response_unsupported("u"),
                Disposition::Fatal,
            ),
            (
                KernelError::active_response_in("step", std::fmt::Error),
                Disposition::Fatal,
            ),
        ] {
            assert_eq!(error.disposition(), expected, "{error:?}");
        }
    }
}
