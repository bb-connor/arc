//! Shared typed, fallible clock for portable capability evaluation.

#[cfg(feature = "std")]
pub use chio_security_types::clock::SystemClock;
pub use chio_security_types::clock::{
    Clock, ClockError, ClockFence, ClockReading, FixedClock, MonotonicInstant, UnixMillis,
};
