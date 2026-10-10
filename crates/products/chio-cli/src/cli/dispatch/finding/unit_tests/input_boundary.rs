use super::*;

pub(super) fn assert_too_large(error: CliError, expected_bound: usize) {
    let CliError::Io(source) = error else {
        panic!("expected typed byte-bound rejection: {error}");
    };
    assert!(
        matches!(source.get_ref().and_then(|cause| cause.downcast_ref::<chio_core::canonical::UntrustedJsonError>()),
        Some(chio_core::canonical::UntrustedJsonError::TooLarge { bound, bytes }) if *bound == expected_bound && *bytes == expected_bound + 1)
    );
}
