//! Scoped fixture control over an explicitly injected clock instance.
//!
//! Production constructors never consult this module. The injected Arc carries
//! its reading across threads; the thread-local only selects a fixture instance.

use chio_security_types::clock::{Clock, ClockError, ClockReading, SystemClock, UnixMillis};
use std::sync::{Arc, Mutex};

thread_local! {
    static FIXTURE: Arc<FixtureClock> = Arc::new(FixtureClock::default());
}

#[derive(Default)]
struct FixtureClock {
    seconds: Mutex<Option<u64>>,
}

impl Clock for FixtureClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let current = SystemClock.read()?;
        let seconds = *self.seconds.lock().map_err(|_| ClockError::Unavailable)?;
        Ok(ClockReading::new(
            match seconds {
                Some(seconds) => UnixMillis::from_secs(seconds)?,
                None => current.unix_millis(),
            },
            current.monotonic(),
        ))
    }
}

/// Select the fixture's explicit time port for a constructor.
pub fn clock() -> Arc<dyn Clock> {
    FIXTURE.with(|clock| clock.clone())
}

/// Restore this clock instance, even if the guard moves to another thread.
pub struct ClockScope {
    clock: Arc<FixtureClock>,
    previous: Option<u64>,
}

impl Drop for ClockScope {
    fn drop(&mut self) {
        use crate::ctx::TestUnwrap;
        *self.clock.seconds.lock().test_unwrap("fixture clock lock") = self.previous;
    }
}

pub fn scope_unix_secs(seconds: u64) -> ClockScope {
    use crate::ctx::TestUnwrap;
    FIXTURE.with(|clock| {
        let previous = clock
            .seconds
            .lock()
            .test_unwrap("fixture clock lock")
            .replace(seconds);
        ClockScope {
            clock: clock.clone(),
            previous,
        }
    })
}

pub fn scoped_unix_secs() -> Option<u64> {
    use crate::ctx::TestUnwrap;
    FIXTURE.with(|clock| *clock.seconds.lock().test_unwrap("fixture clock lock"))
}

pub fn unix_millis() -> u64 {
    use crate::ctx::TestUnwrap;
    clock()
        .unix_millis()
        .test_unwrap("fixture clock reading")
        .get()
}

pub fn unix_seconds() -> u64 {
    unix_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_clock_follows_its_owner_across_threads() -> Result<(), Box<dyn std::error::Error>> {
        let injected = clock();
        let before = injected.unix_millis()?.get();
        let scope = scope_unix_secs(42);
        let worker = std::thread::spawn(move || injected.unix_millis());
        let observed = worker.join().map_err(|_| "clock worker panicked")??;
        assert_eq!(observed.get(), 42_000);
        drop(scope);
        assert!(clock().unix_millis()?.get() >= before);
        Ok(())
    }

    #[test]
    fn separate_fixture_threads_have_independent_clocks() -> Result<(), Box<dyn std::error::Error>>
    {
        let _scope = scope_unix_secs(1);
        let worker = std::thread::spawn(|| {
            let _scope = scope_unix_secs(2);
            clock().unix_millis()
        });
        assert_eq!(
            worker.join().map_err(|_| "clock worker panicked")??.get(),
            2_000
        );
        assert_eq!(clock().unix_millis()?.get(), 1_000);
        Ok(())
    }
}
