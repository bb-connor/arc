//! Owned nonce reservations retained through their exact signed expiry.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chio_security_types::clock::{Clock, ClockError, ClockFence, SystemClock, UnixMillis};

use super::{ExecutionNonceConfig, ExecutionNonceStore, DEFAULT_EXECUTION_NONCE_STORE_CAPACITY};
use crate::KernelError;

pub struct InMemoryExecutionNonceStore {
    capacity: usize,
    clock: Arc<dyn Clock>,
    inner: Mutex<State>,
}
struct State {
    cache: HashMap<String, Entry>,
    fence: ClockFence,
}
struct Entry {
    retain_until: UnixMillis,
    reservation_id: Option<String>,
}

impl InMemoryExecutionNonceStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_clock(capacity, Arc::new(SystemClock))
    }

    #[must_use]
    pub fn with_clock(capacity: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            capacity,
            clock,
            inner: Mutex::new(State {
                cache: HashMap::new(),
                fence: ClockFence::default(),
            }),
        }
    }

    #[must_use]
    pub fn from_config(config: &ExecutionNonceConfig) -> Self {
        Self::new(config.nonce_store_capacity)
    }

    fn reserve_signed(
        &self,
        nonce_id: &str,
        expires_at: i64,
        owner: Option<&str>,
    ) -> Result<bool, KernelError> {
        if nonce_id.is_empty()
            || nonce_id.trim() != nonce_id
            || owner.is_some_and(|id| id.is_empty() || id.trim() != id)
        {
            return Err(KernelError::InvalidConstraint(
                "nonce reservation identifier is empty or padded".into(),
            ));
        }
        let expires_at = u64::try_from(expires_at).map_err(|_| ClockError::BeforeEpoch)?;
        let retain_until = UnixMillis::from_secs(expires_at)?;
        let mut state = self.inner.lock().map_err(|_| ClockError::Unavailable)?;
        let now = state.fence.observe(self.clock.read()?)?.unix_millis();
        if retain_until <= now {
            return Err(ClockError::Expired.into());
        }
        // Compute all fallible inputs before mutation. Never evict a live replay
        // marker to admit another nonce, and never use elapsed monotonic time to
        // forget a marker while its signed epoch window is still valid.
        if state
            .cache
            .get(nonce_id)
            .is_some_and(|entry| entry.retain_until > now)
        {
            return Ok(false);
        }
        let expired: Vec<_> = state
            .cache
            .iter()
            .filter(|(_, entry)| entry.retain_until <= now)
            .map(|(id, _)| id.clone())
            .collect();
        if state
            .cache
            .len()
            .checked_sub(expired.len())
            .ok_or(ClockError::Overflow)?
            >= self.capacity
        {
            return Err(KernelError::ExecutionNonceCapacity);
        }
        for id in expired {
            state.cache.remove(&id);
        }
        state.cache.insert(
            nonce_id.to_owned(),
            Entry {
                retain_until,
                reservation_id: owner.map(str::to_owned),
            },
        );
        Ok(true)
    }
}
impl Default for InMemoryExecutionNonceStore {
    fn default() -> Self {
        Self::new(DEFAULT_EXECUTION_NONCE_STORE_CAPACITY)
    }
}
impl ExecutionNonceStore for InMemoryExecutionNonceStore {
    fn reserve_until(&self, nonce_id: &str, expires_at: i64) -> Result<bool, KernelError> {
        self.reserve_signed(nonce_id, expires_at, None)
    }
    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        expires_at: i64,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_signed(nonce_id, expires_at, Some(owner))
    }
    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        let mut state = self.inner.lock().map_err(|_| ClockError::Unavailable)?;
        // Rollback proves nonexecution and removes only this attempt's marker;
        // it must remain available when the clock that caused denial is down.
        let owned = state
            .cache
            .get(nonce_id)
            .is_some_and(|entry| entry.reservation_id.as_deref() == Some(owner));
        if owned {
            state.cache.remove(nonce_id);
        }
        Ok(owned)
    }
    fn is_consumed(&self, nonce_id: &str) -> Result<bool, KernelError> {
        let mut state = self.inner.lock().map_err(|_| ClockError::Unavailable)?;
        let now = state.fence.observe(self.clock.read()?)?.unix_millis();
        Ok(state
            .cache
            .get(nonce_id)
            .is_some_and(|entry| entry.retain_until > now))
    }
}

#[cfg(test)]
mod tests;
