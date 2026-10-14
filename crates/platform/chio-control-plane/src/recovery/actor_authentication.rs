//! Closed policy denials and operational authentication failures stay distinct.
use super::RecoveryRuntimeError;
use chio_kernel::KernelError;

pub(crate) fn authentication_error(error: KernelError) -> RecoveryRuntimeError {
    #[cfg(test)]
    eprintln!(
        "recovery typed kernel refusal: {error:?}\n{}",
        std::backtrace::Backtrace::force_capture()
    );
    match error {
        KernelError::RecoveryMediationRequired => RecoveryRuntimeError::UncoveredMediation,
        KernelError::RecoveryAuthorityDenied
        | KernelError::CapabilityExpired
        | KernelError::CapabilityNotYetValid
        | KernelError::CapabilityRevoked(_)
        | KernelError::InvalidSignature
        | KernelError::UntrustedIssuer
        | KernelError::OutOfScope { .. }
        | KernelError::OutOfScopeResource { .. }
        | KernelError::OutOfScopePrompt { .. }
        | KernelError::SubjectMismatch { .. }
        | KernelError::DelegationChainRevoked(_)
        | KernelError::DelegationInvalid(_)
        | KernelError::InvalidConstraint(_) => RecoveryRuntimeError::AuthorityDenied,
        _ => RecoveryRuntimeError::Unavailable,
    }
}
