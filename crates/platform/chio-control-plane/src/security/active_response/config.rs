use chio_kernel::ActiveResponseExecutorError;
use chio_security_types::ports::PortResult;

use super::{DurableActiveResponseExecutorConfigError, MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS};

pub(super) fn validate_lease_duration(
    lease_duration_ms: u64,
) -> Result<(), DurableActiveResponseExecutorConfigError> {
    if lease_duration_ms == 0 {
        return Err(DurableActiveResponseExecutorConfigError::ZeroLeaseDuration);
    }
    if lease_duration_ms > MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS {
        return Err(
            DurableActiveResponseExecutorConfigError::LeaseDurationTooLong {
                actual_ms: lease_duration_ms,
                maximum_ms: MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS,
            },
        );
    }
    Ok(())
}

pub(super) fn readiness(
    component: &str,
    result: PortResult<()>,
) -> Result<(), ActiveResponseExecutorError> {
    result.map_err(|error| {
        ActiveResponseExecutorError::NotReady(format!("{component} readiness failed: {error}"))
    })
}
