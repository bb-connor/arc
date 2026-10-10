//! One injected clock owner for OAuth custody and lifecycle observations.
use super::*;

#[derive(Clone)]
pub(super) struct ClockSource(pub(super) Arc<dyn Clock>);
impl std::fmt::Debug for ClockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClockSource")
    }
}
impl Default for ClockSource {
    fn default() -> Self {
        Self(Arc::new(SystemClock))
    }
}
impl Clock for ClockSource {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.0.read()
    }
}
