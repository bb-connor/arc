//! Public categories distinguish native policy refusal from retained custody faults.
use super::*;
use chio_kernel::admission_operation::{AdmissionOperationError, AdmissionOperationStoreError};

fn classify(error: AdmissionOperationStoreError) -> RecoveryRuntimeError {
    store_error(error)
}

#[test]
fn an_explicit_native_authority_denial_keeps_its_closed_category() {
    assert_eq!(
        classify(AdmissionOperationStoreError::RecoveryAuthorityDenied),
        RecoveryRuntimeError::AuthorityDenied,
    );
}

#[test]
fn required_native_mediation_keeps_its_closed_category() {
    assert_eq!(
        classify(AdmissionOperationStoreError::RecoveryMediationRequired),
        RecoveryRuntimeError::UncoveredMediation,
    );
}

#[test]
fn a_retained_custody_invariant_is_an_operational_refusal() {
    assert_eq!(
        classify(AdmissionOperationStoreError::Invariant(
            "private-native-custody-canary".to_owned(),
        )),
        RecoveryRuntimeError::Unavailable,
    );
}

#[test]
fn an_authenticated_terminal_projection_mismatch_is_an_operational_refusal() {
    assert_eq!(
        classify(AdmissionOperationStoreError::Operation(
            AdmissionOperationError::TerminalReplayMismatch,
        )),
        RecoveryRuntimeError::Unavailable,
    );
}

#[test]
fn existing_operational_families_keep_their_closed_category() {
    for error in [
        AdmissionOperationStoreError::Unavailable("private-backend-canary".to_owned()),
        AdmissionOperationStoreError::OutcomeUnknown("private-outcome-canary".to_owned()),
        AdmissionOperationStoreError::Fenced,
    ] {
        assert_eq!(classify(error), RecoveryRuntimeError::Unavailable);
    }
}
