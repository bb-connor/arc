//! A transport budget constrains observation readiness and grants no authority.
use core::time::Duration;

/// The original affine lookup may live for at most this interval, further
/// capped by the current settlement capability. Reservation never renews it.
pub const MAX_RECOVERY_PROVIDER_OBSERVATION_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryProviderLookupBudget {
    request_millis: u64,
}
impl RecoveryProviderLookupBudget {
    pub fn from_duration(duration: Duration) -> Result<Self, crate::KernelError> {
        let fraction = u128::from(duration.subsec_nanos() % 1_000_000 != 0);
        let millis = duration
            .as_millis()
            .checked_add(fraction)
            .and_then(|millis| u64::try_from(millis).ok())
            .filter(|millis| (1..=MAX_RECOVERY_PROVIDER_OBSERVATION_MS).contains(millis))
            .ok_or_else(|| {
                crate::KernelError::DurableAdmission(
                    "recovery provider request budget is unsupported".into(),
                )
            })?;
        Ok(Self {
            request_millis: millis,
        })
    }
    pub const fn request_millis(self) -> u64 {
        self.request_millis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_budget_rounds_up_without_shortening_the_actual_transport() {
        for (duration, expected) in [
            (Duration::from_nanos(1), 1),
            (Duration::from_micros(1501), 2),
            (Duration::from_millis(20_123), 20_123),
            (Duration::from_secs(60), 60_000),
        ] {
            let result = RecoveryProviderLookupBudget::from_duration(duration);
            assert!(matches!(result, Ok(budget) if budget.request_millis() == expected));
        }
    }

    #[test]
    fn provider_budget_refuses_zero_overflow_and_the_original_lookup_ceiling() {
        for duration in [
            Duration::ZERO,
            Duration::from_secs(60) + Duration::from_nanos(1),
            Duration::MAX,
        ] {
            assert!(RecoveryProviderLookupBudget::from_duration(duration).is_err());
        }
    }
}
