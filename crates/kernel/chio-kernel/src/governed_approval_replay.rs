//! Replay prevention for governed approval tokens at the dispatch boundary.

use chio_security_types::clock::{Clock, SystemClock};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use tracing::error;

use crate::replay_retention::{ReplayClock, ReplayHorizon, ReplayRetention};
use crate::KernelError;

/// Refusal rules of the process-local approval custody store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalReplayError {
    #[error("approval replay store unavailable; marker retained")]
    Unavailable,
    #[error("approval replay store capacity exhausted")]
    Capacity,
    #[error("approval replay identity must be non-empty and unpadded")]
    Identity,
    #[error("approval expired before replay reservation")]
    Expired,
}
impl ApprovalReplayError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => "urn:chio:error:kernel:approval-replay-unavailable",
            Self::Capacity => "urn:chio:error:kernel:approval-replay-capacity",
            Self::Identity => "urn:chio:error:kernel:approval-replay-identity",
            Self::Expired => "urn:chio:error:kernel:approval-replay-expired",
        }
    }
}

/// Default number of live governed approvals retained by the in-memory store.
pub const DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY: usize = 8192;

/// Atomic reservation store for single-use governed approvals.
///
/// A reservation is owned until it is either committed or rolled back. Commit
/// retains the replay marker but clears rollback ownership. Implementations
/// must leave the marker replay-blocking when commit returns `false` or an
/// error because a dispatch or external payment may already have happened.
/// Kernel construction installs a process-local store. Embedding hosts must
/// select a durable implementation when replay protection must survive restart.
pub trait GovernedApprovalReplayStore: Send + Sync {
    /// Reserve a `(subject_id, request_id, intent_hash)` tuple until its signed
    /// expiry. Capacity is store-global; multi-tenant hosts should isolate
    /// tenants in separate kernels or enforce upstream admission limits.
    fn reserve_for_dispatch(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;

    /// Commit a reservation owned by `reservation_id` without removing it.
    fn commit_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;

    /// Remove a reservation only when `reservation_id` still owns it.
    fn rollback_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;
}

/// Process-scoped governed approval replay store.
///
/// Kernel construction binds this default store to the kernel's clock. Use a
/// durable implementation when replay protection must survive restart.
pub struct InMemoryGovernedApprovalReplayStore {
    inner: Mutex<ApprovalReplayState>,
    clock: Arc<dyn Clock>,
}

struct ApprovalReplayState {
    cache: LruCache<(String, String, String), ApprovalReplayEntry>,
    replay_clock: ReplayClock,
}

struct ApprovalReplayEntry {
    retention: ReplayRetention,
    reservation_id: Option<String>,
}

impl InMemoryGovernedApprovalReplayStore {
    /// # Panics
    ///
    /// Panics when `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_clock(capacity, Arc::new(SystemClock))
    }
    pub fn with_clock(capacity: usize, clock: Arc<dyn Clock>) -> Self {
        let capacity = match NonZeroUsize::new(capacity) {
            Some(capacity) => capacity,
            None => panic!("governed approval replay capacity must be greater than zero"),
        };
        Self {
            inner: Mutex::new(ApprovalReplayState {
                cache: LruCache::new(capacity),
                replay_clock: ReplayClock::default(),
            }),
            clock,
        }
    }

    fn reserve(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        validate_key_part("subject_id", subject_id)?;
        validate_key_part("request_id", request_id)?;
        validate_key_part("intent_hash", intent_hash)?;
        validate_key_part("reservation_id", reservation_id)?;

        let key = (
            subject_id.to_string(),
            request_id.to_string(),
            intent_hash.to_string(),
        );
        let mut state = self.inner.lock().map_err(|_| {
            error!("governed approval replay store mutex poisoned; denying fail-closed");
            KernelError::ApprovalReplay(ApprovalReplayError::Unavailable)
        })?;

        let now = state
            .replay_clock
            .observe("governed_approval", self.clock.read()?)?;
        let retention = ReplayHorizon::Until(expires_at).project(now);

        if state
            .cache
            .peek(&key)
            .is_some_and(|entry| !entry.retention.is_expired_at(now))
        {
            return Ok(false);
        }

        let expired_keys = state
            .cache
            .iter()
            .filter(|(_, entry)| entry.retention.is_expired_at(now))
            .map(|(expired_key, _)| expired_key.clone())
            .collect::<Vec<_>>();
        for expired_key in expired_keys {
            state.cache.pop(&expired_key);
        }

        if retention.signed_horizon_elapsed_at(now.unix_millis()) {
            error!("elapsed approval horizon; denying replay reservation");
            return Err(ApprovalReplayError::Expired.into());
        }
        if state.cache.len() >= state.cache.cap().get() {
            error!(
                capacity = state.cache.cap().get(),
                "governed approval replay store capacity exhausted; denying fail-closed"
            );
            return Err(KernelError::ApprovalReplay(ApprovalReplayError::Capacity));
        }

        state.cache.put(
            key,
            ApprovalReplayEntry {
                retention,
                reservation_id: Some(reservation_id.to_string()),
            },
        );
        Ok(true)
    }
}

impl Default for InMemoryGovernedApprovalReplayStore {
    fn default() -> Self {
        Self::new(DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY)
    }
}

impl GovernedApprovalReplayStore for InMemoryGovernedApprovalReplayStore {
    fn reserve_for_dispatch(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve(
            subject_id,
            request_id,
            intent_hash,
            expires_at,
            reservation_id,
        )
    }

    fn commit_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let key = (
            subject_id.to_string(),
            request_id.to_string(),
            intent_hash.to_string(),
        );
        let mut state = self
            .inner
            .lock()
            .map_err(|_| KernelError::ApprovalReplay(ApprovalReplayError::Unavailable))?;
        let Some(entry) = state.cache.peek_mut(&key) else {
            return Ok(false);
        };
        if entry.reservation_id.as_deref() != Some(reservation_id) {
            return Ok(false);
        }
        entry.reservation_id = None;
        Ok(true)
    }

    fn rollback_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let key = (
            subject_id.to_string(),
            request_id.to_string(),
            intent_hash.to_string(),
        );
        let mut state = self
            .inner
            .lock()
            .map_err(|_| KernelError::ApprovalReplay(ApprovalReplayError::Unavailable))?;
        let owned = state
            .cache
            .peek(&key)
            .is_some_and(|entry| entry.reservation_id.as_deref() == Some(reservation_id));
        if owned {
            state.cache.pop(&key);
        }
        Ok(owned)
    }
}

fn validate_key_part(_name: &str, value: &str) -> Result<(), KernelError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(ApprovalReplayError::Identity.into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
