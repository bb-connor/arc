use super::*;

fn guard_error(result: Result<(), AcpProxyError>) -> AcpGuardError {
    match result {
        Err(AcpProxyError::Guard(error)) => error,
        other => panic!("expected a guard refusal, got {other:?}"),
    }
}

#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "tests/attestation_support.rs"]
mod attestation_and_telemetry_tests;
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "tests/extended_support.rs"]
mod extended_tests;
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "tests/core_support.rs"]
mod scenarios;
