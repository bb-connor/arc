//! Production refusal codes must retain the diagnostic metadata clients consume.

use chio_errors::{lookup_error_code, Domain, Severity};
use chio_kernel::{
    dpop::{DpopError, DpopProof},
    governed_approval_replay::ApprovalReplayError,
    DpopNonceStore, InMemoryGovernedApprovalReplayStore,
};
use std::time::Duration;

fn assert_registered_kernel_refusal(urn: &str, expected_string_code: &str) {
    let spec = lookup_error_code(urn)
        .unwrap_or_else(|| panic!("production refusal is absent from registry: {urn}"));
    assert_eq!(spec.domain, Domain::Kernel);
    assert_eq!(spec.severity, Severity::Error);
    assert_eq!(spec.string_code, expected_string_code);
    assert!(!spec.summary.is_empty());
    assert!(!spec.help.is_empty());
    assert!(spec.consumed_by.contains(&"chio-kernel"));
    let report = chio_control_plane::CliError::registry_error(spec, "boundary refused").report();
    assert_eq!(report.code, urn);
    assert_eq!(report.context["severity"], "error");
    assert_eq!(report.context["string_code"], expected_string_code);
    assert_eq!(report.suggested_fix, spec.help);
}

#[test]
fn zero_dpop_capacity_emits_registered_diagnostic() {
    let error = match DpopNonceStore::new(0, Duration::from_secs(60)) {
        Err(error) => error,
        Ok(_) => panic!("zero-capacity DPoP store constructed"),
    };
    assert!(matches!(error, DpopError::InvalidCapacity(_)));
    assert_registered_kernel_refusal(error.code(), "CHIO-KERNEL-DPOP-INVALID-CAPACITY");
}

#[test]
fn malformed_dpop_proof_emits_registered_diagnostic() {
    let source = match serde_json::from_str::<DpopProof>("{}") {
        Err(error) => error,
        Ok(_) => panic!("missing DPoP proof fields decoded"),
    };
    let error = DpopError::Malformed(source);
    assert!(std::error::Error::source(&error).is_some());
    let report = chio_kernel::KernelError::Dpop(error).report();
    assert_registered_kernel_refusal(&report.code, "CHIO-KERNEL-DPOP-MALFORMED");
    let spec = lookup_error_code(&report.code)
        .unwrap_or_else(|| panic!("malformed proof diagnostic was not registered"));
    assert!(spec.consumed_by.contains(&"chio-mcp-edge"));
}

#[test]
fn zero_approval_capacity_emits_registered_diagnostic() {
    let error = match InMemoryGovernedApprovalReplayStore::new(0) {
        Err(error) => error,
        Ok(_) => panic!("zero-capacity approval store constructed"),
    };
    assert!(matches!(error, ApprovalReplayError::InvalidCapacity));
    assert_registered_kernel_refusal(error.code(), "CHIO-KERNEL-APPROVAL-REPLAY-INVALID-CAPACITY");
}
