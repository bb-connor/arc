//! Executor clock custody independent of the kernel and its admission ledger.
use super::{invalid, storage, Result};
use chio_security_types::clock::{Clock, ClockFence};
use std::sync::{Arc, Mutex};

pub(super) struct LedgerClock {
    source: Arc<dyn Clock>,
    fence: Mutex<ClockFence>,
}

impl LedgerClock {
    pub(super) fn new(source: Arc<dyn Clock>) -> Self {
        Self {
            source,
            fence: Mutex::new(ClockFence::default()),
        }
    }

    pub(super) fn now_ms(&self) -> Result<i64> {
        let mut fence = self
            .fence
            .lock()
            .map_err(|_| invalid("executor clock fence poisoned"))?;
        let value = fence
            .observe(self.source.read().map_err(storage)?)
            .map_err(storage)?
            .unix_millis()
            .get();
        if value == 0 || value >= (1_u64 << 53) {
            return Err(invalid("executor clock is outside I-JSON range"));
        }
        i64::try_from(value).map_err(storage)
    }
}
