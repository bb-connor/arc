use super::*;
use crate::admission_operation::{
    AdmissionOperationError, AdmissionOperationStoreError, AdmissionRecoveryError,
    AdmissionRecoveryFailureKind as Kind,
};
use crate::disposition::Disposition;
use crate::finding_denial::{FindingDenial, FindingDenialCode};
use chio_security_types::clock::ClockError;

#[test]
fn each_item_failure_kind_has_one_item_scoped_disposition() {
    for (kind, expected) in [
        (Kind::ParticipantUnavailable, Disposition::Retry),
        (Kind::PaymentPending, Disposition::Retry),
        (Kind::OutputDenied, Disposition::Deny),
        (Kind::ContractChanged, Disposition::Quarantine),
        (Kind::RecoveryRequestAbsent, Disposition::Quarantine),
        (Kind::UnsupportedState, Disposition::Quarantine),
        (Kind::LegacyPaymentAmountAbsent, Disposition::Quarantine),
    ] {
        assert_eq!(kind.disposition(), expected, "{kind:?}");
        assert_eq!(
            disposition(&item_failure(kind, "one operation")),
            expected,
            "{kind:?}"
        );
        assert!(expected.is_item_scoped(), "{kind:?}");
    }
}

#[test]
fn shared_and_unclassified_faults_stop_the_sweep() {
    let faults = [
        KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::Store(
            AdmissionOperationStoreError::Invariant("shared journal".into()),
        ))),
        operation_error(AdmissionOperationError::Clock(ClockError::Unavailable)),
        KernelError::Clock(ClockError::Unavailable),
        KernelError::DurableAdmission("unclassified".into()),
        KernelError::Internal("unclassified".into()),
    ];
    for fault in &faults {
        assert_eq!(disposition(fault), Disposition::Fatal, "{fault}");
        assert_eq!(classify(fault), None, "{fault}");
    }
    assert!(!Disposition::Fatal.is_item_scoped());
}

#[test]
fn authority_refusals_deny_and_an_unavailable_finding_retries() {
    for refusal in [
        KernelError::GuardDenied("guard refused the output".into()),
        KernelError::CapabilityRevoked("capability".into()),
        KernelError::DelegationChainRevoked("delegation".into()),
        KernelError::FindingDenied(FindingDenial::new(
            FindingDenialCode::AuthorityInvalid,
            "authority",
        )),
    ] {
        assert_eq!(disposition(&refusal), Disposition::Deny, "{refusal}");
    }
    assert_eq!(
        disposition(&KernelError::FindingDenied(FindingDenial::new(
            FindingDenialCode::Unavailable,
            "status feed down",
        ))),
        Disposition::Retry
    );
}

#[test]
fn the_sweep_agrees_with_the_general_classifier_whenever_it_can_defer() {
    let deferrable = [
        item_failure(Kind::ParticipantUnavailable, "participant"),
        item_failure(Kind::ContractChanged, "contract"),
        KernelError::GuardDenied("guard refused the output".into()),
        KernelError::CapabilityRevoked("capability".into()),
        KernelError::FindingDenied(FindingDenial::new(
            FindingDenialCode::Unavailable,
            "status feed down",
        )),
        KernelError::FindingDenied(FindingDenial::new(
            FindingDenialCode::StatusDenied,
            "retracted",
        )),
    ];
    for error in &deferrable {
        assert!(classify(error).is_some(), "{error}");
        assert_eq!(disposition(error), error.disposition(), "{error}");
    }
}

#[test]
fn the_sweep_stops_on_typed_admission_failures_it_cannot_record() {
    let typed = [
        KernelError::admission_refused("refused"),
        KernelError::admission_pending("owned elsewhere"),
        KernelError::admission(AdmissionOperationStoreError::Unavailable("down".into())),
        KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::Store(
            AdmissionOperationStoreError::Unavailable("down".into()),
        ))),
    ];
    for error in &typed {
        assert_eq!(classify(error), None, "{error}");
        assert_eq!(disposition(error), Disposition::Fatal, "{error}");
        assert!(error.disposition().is_item_scoped(), "{error}");
    }
}
