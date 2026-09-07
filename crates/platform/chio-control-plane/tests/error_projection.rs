//! Stable public error paths and diagnostic projection after module separation.

use chio_control_plane::CliError;
use chio_errors::ChioError;
use chio_errors::_generated::error_codes::GUARD_DENIED;

#[test]
fn registry_error_preserves_the_normative_code_and_metadata() {
    let expected = ChioError::from_spec(&GUARD_DENIED, "blocked by policy");
    let report = CliError::guard_error("blocked by policy").report();
    assert_eq!(report.code, expected.diagnostic().code().as_str());
    assert_eq!(report.message, expected.diagnostic().message());
    assert_eq!(report.context["string_code"], GUARD_DENIED.string_code);
    assert!(!report.suggested_fix.is_empty());
}

#[test]
fn io_and_unclassified_errors_retain_distinct_diagnostic_context() {
    let io = CliError::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "custody file unavailable",
    ))
    .report();
    let other = CliError::Other("configuration incomplete".into()).report();
    assert_eq!(io.code, "CHIO-CLI-IO");
    assert_eq!(io.context["source"], "custody file unavailable");
    assert_eq!(other.code, "CHIO-CLI-OTHER");
    assert_eq!(other.context["detail"], "configuration incomplete");
    assert_ne!(io.suggested_fix, other.suggested_fix);
}
