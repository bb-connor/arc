//! Browser time adapter. Invalid host readings are errors, never epoch zero.
use chio_kernel_core::clock::{Clock, ClockError, ClockReading};
#[derive(Debug, Default, Clone, Copy)]
pub struct BrowserClock;
impl BrowserClock {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
impl Clock for BrowserClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        #[cfg(target_arch = "wasm32")]
        {
            use chio_kernel_core::clock::ClockFence;
            std::thread_local! { static FENCE: core::cell::RefCell<ClockFence> = core::cell::RefCell::new(ClockFence::default()); }
            let millis = js_sys::Date::now();
            let global = js_sys::global();
            let performance = js_sys::Reflect::get(&global, &"performance".into())
                .map_err(|_| ClockError::Unavailable)?;
            let now = js_sys::Reflect::get(&performance, &"now".into())
                .map_err(|_| ClockError::Unavailable)?;
            use wasm_bindgen::JsCast;
            let function = now
                .dyn_ref::<js_sys::Function>()
                .ok_or(ClockError::Unavailable)?;
            let ticks = function
                .call0(&performance)
                .map_err(|_| ClockError::Unavailable)?
                .as_f64()
                .ok_or(ClockError::Unavailable)?
                * 1_000_000.0;
            let reading = checked_host_reading(millis, ticks)?;
            FENCE.with(|fence| fence.borrow_mut().observe(reading))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Err(ClockError::Unavailable)
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
#[allow(
    clippy::as_conversions,
    reason = "Both host floats are finite, nonnegative and strictly below 2^64 before truncation to integer clock units."
)]
fn checked_host_reading(millis: f64, ticks: f64) -> Result<ClockReading, ClockError> {
    use chio_kernel_core::clock::{MonotonicInstant, UnixMillis};
    // 2^64 is exactly representable. Casting u64::MAX to f64 rounds up to it.
    const U64_EXCLUSIVE_MAX: f64 = 18_446_744_073_709_551_616.0;
    if !millis.is_finite() || !ticks.is_finite() {
        return Err(ClockError::Unavailable);
    }
    if millis < 0.0 || ticks < 0.0 {
        return Err(ClockError::BeforeEpoch);
    }
    if millis >= U64_EXCLUSIVE_MAX || ticks >= U64_EXCLUSIVE_MAX {
        return Err(ClockError::Overflow);
    }
    Ok(ClockReading::new(
        UnixMillis::new(millis as u64),
        MonotonicInstant::from_nanos(ticks as u64),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel_core::clock::{MonotonicInstant, UnixMillis};

    #[test]
    fn host_clock_rejects_invalid_values_in_either_domain() {
        for (value, error) in [
            (f64::NAN, ClockError::Unavailable),
            (f64::INFINITY, ClockError::Unavailable),
            (f64::NEG_INFINITY, ClockError::Unavailable),
            (-1.0, ClockError::BeforeEpoch),
            (18_446_744_073_709_551_616.0, ClockError::Overflow),
        ] {
            assert_eq!(checked_host_reading(value, 0.0), Err(error));
            assert_eq!(checked_host_reading(0.0, value), Err(error));
        }
    }

    #[test]
    fn host_clock_preserves_zero_truncation_and_last_representable_value() -> Result<(), ClockError>
    {
        assert_eq!(
            checked_host_reading(-0.0, 0.0)?,
            ClockReading::new(UnixMillis::new(0), MonotonicInstant::from_nanos(0))
        );
        assert_eq!(
            checked_host_reading(12.999, 34.125)?,
            ClockReading::new(UnixMillis::new(12), MonotonicInstant::from_nanos(34))
        );
        let upper_bound = 18_446_744_073_709_551_616.0_f64;
        let last = f64::from_bits(upper_bound.to_bits() - 1);
        assert_eq!(
            checked_host_reading(last, last)?,
            ClockReading::new(
                UnixMillis::new(u64::MAX - 2047),
                MonotonicInstant::from_nanos(u64::MAX - 2047),
            )
        );
        Ok(())
    }
}
