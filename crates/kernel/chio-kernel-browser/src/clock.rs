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
            use chio_kernel_core::clock::{ClockFence, MonotonicInstant, UnixMillis};
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
            if !millis.is_finite() || !ticks.is_finite() {
                return Err(ClockError::Unavailable);
            }
            if millis < 0.0 || ticks < 0.0 {
                return Err(ClockError::BeforeEpoch);
            }
            if millis >= u64::MAX as f64 || ticks >= u64::MAX as f64 {
                return Err(ClockError::Overflow);
            }
            let reading = ClockReading::new(
                UnixMillis::new(millis as u64),
                MonotonicInstant::from_nanos(ticks as u64),
            );
            FENCE.with(|fence| fence.borrow_mut().observe(reading))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Err(ClockError::Unavailable)
        }
    }
}
