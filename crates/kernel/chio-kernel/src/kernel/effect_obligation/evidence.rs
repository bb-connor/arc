//! Capacity is acquired before dispatch and travels with retained evidence.

use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::recovery::{EvidenceProducer, EvidenceQueue, PendingPostEffectRecord};
use crate::KernelError;

const DEFAULT_HOST_SLOTS: usize = 4096;
const DEFAULT_HOST_BYTES: usize = 64 * 1024 * 1024;
#[cfg(test)]
const DEFAULT_KERNEL_BYTES: usize = 16 * 1024 * 1024;

/// Shared evidence capacity for every kernel hosted by one process.
///
/// Keep one instance for the host and install it on each kernel before serving
/// requests. A pending record holds its permit until its append is resolved.
pub struct PostEffectEvidenceBudget {
    permits: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

impl PostEffectEvidenceBudget {
    pub fn new(slots: NonZeroUsize) -> Result<Self, KernelError> {
        Self::with_byte_limit(
            slots,
            NonZeroUsize::new(DEFAULT_HOST_BYTES).ok_or_else(capacity_error)?,
        )
    }

    pub fn with_byte_limit(slots: NonZeroUsize, bytes: NonZeroUsize) -> Result<Self, KernelError> {
        if slots.get() > Semaphore::MAX_PERMITS || bytes.get() > Semaphore::MAX_PERMITS {
            return Err(KernelError::Internal(
                "post-effect evidence capacity exceeds semaphore limit".into(),
            ));
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(slots.get())),
            bytes: Arc::new(Semaphore::new(bytes.get())),
        })
    }

    pub(in crate::kernel) fn process_default() -> Arc<Self> {
        static BUDGET: OnceLock<Arc<PostEffectEvidenceBudget>> = OnceLock::new();
        Arc::clone(BUDGET.get_or_init(|| {
            Arc::new(Self {
                permits: Arc::new(Semaphore::new(DEFAULT_HOST_SLOTS)),
                bytes: Arc::new(Semaphore::new(DEFAULT_HOST_BYTES)),
            })
        }))
    }
}

pub(super) struct EvidencePool {
    permits: Arc<Semaphore>,
    capacity: usize,
    bytes: Arc<Semaphore>,
    host: Arc<PostEffectEvidenceBudget>,
}

impl EvidencePool {
    #[cfg(test)]
    pub(super) fn new(
        slots: NonZeroUsize,
        host: Arc<PostEffectEvidenceBudget>,
    ) -> Result<Self, KernelError> {
        Self::with_byte_limit(
            slots,
            NonZeroUsize::new(DEFAULT_KERNEL_BYTES).ok_or_else(capacity_error)?,
            host,
        )
    }

    pub(super) fn with_byte_limit(
        slots: NonZeroUsize,
        bytes: NonZeroUsize,
        host: Arc<PostEffectEvidenceBudget>,
    ) -> Result<Self, KernelError> {
        if slots.get() > Semaphore::MAX_PERMITS || bytes.get() > Semaphore::MAX_PERMITS {
            return Err(KernelError::Internal(
                "post-effect evidence capacity exceeds semaphore limit".into(),
            ));
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(slots.get())),
            bytes: Arc::new(Semaphore::new(bytes.get())),
            capacity: slots.get(),
            host,
        })
    }

    pub(super) fn is_idle(&self) -> bool {
        self.permits.available_permits() == self.capacity
    }

    pub(super) fn acquire(
        &self,
        queue: Arc<EvidenceQueue>,
        bytes: NonZeroUsize,
    ) -> Result<EvidenceSlot, KernelError> {
        let kernel = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| capacity_error())?;
        let host = Arc::clone(&self.host.permits)
            .try_acquire_owned()
            .map_err(|_| capacity_error())?;
        let count = u32::try_from(bytes.get()).map_err(|_| capacity_error())?;
        let kernel_bytes = Arc::clone(&self.bytes)
            .try_acquire_many_owned(count)
            .map_err(|_| capacity_error())?;
        let host_bytes = Arc::clone(&self.host.bytes)
            .try_acquire_many_owned(count)
            .map_err(|_| capacity_error())?;
        Ok(EvidenceSlot {
            kernel,
            host,
            queue: queue.register_producer(),
            kernel_bytes,
            host_bytes,
        })
    }
}

fn capacity_error() -> KernelError {
    KernelError::PostEffectEvidenceCapacity
}

/// There is no independent release method: only dropping this owner returns
/// capacity. Moving it into a buffered record keeps both budgets charged.
pub(in crate::kernel) struct EvidenceSlot {
    kernel: OwnedSemaphorePermit,
    host: OwnedSemaphorePermit,
    queue: EvidenceProducer,
    kernel_bytes: OwnedSemaphorePermit,
    host_bytes: OwnedSemaphorePermit,
}

impl EvidenceSlot {
    pub(in crate::kernel) fn reserve_bytes(&mut self, bytes: usize) -> Result<(), KernelError> {
        let count = u32::try_from(bytes).map_err(|_| capacity_error())?;
        let kernel = Arc::clone(self.kernel_bytes.semaphore())
            .try_acquire_many_owned(count)
            .map_err(|_| capacity_error())?;
        let host = Arc::clone(self.host_bytes.semaphore())
            .try_acquire_many_owned(count)
            .map_err(|_| capacity_error())?;
        self.kernel_bytes.merge(kernel);
        self.host_bytes.merge(host);
        Ok(())
    }

    pub(in crate::kernel) fn buffer(self, record: PendingPostEffectRecord) {
        self.queue.queue.buffer(
            record,
            self.kernel,
            self.host,
            self.kernel_bytes,
            self.host_bytes,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acquire(pool: &EvidencePool) -> Result<EvidenceSlot, KernelError> {
        pool.acquire(EvidenceQueue::empty_for_test(), capacity(1))
    }

    fn capacity(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }

    #[test]
    fn host_budget_bounds_distinct_kernel_pools() {
        let host = Arc::new(PostEffectEvidenceBudget::new(capacity(2)).unwrap());
        let first = EvidencePool::new(capacity(2), Arc::clone(&host)).unwrap();
        let second = EvidencePool::new(capacity(2), host).unwrap();
        let one = acquire(&first).unwrap();
        let two = acquire(&second).unwrap();
        assert!(acquire(&first).is_err());
        assert!(acquire(&second).is_err());
        drop(one);
        let replacement = acquire(&second).unwrap();
        assert!(acquire(&first).is_err());
        drop((two, replacement));
        assert!(acquire(&first).is_ok());
    }

    #[test]
    fn failed_host_acquisition_returns_kernel_permit() {
        let host = Arc::new(PostEffectEvidenceBudget::new(capacity(1)).unwrap());
        let first = EvidencePool::new(capacity(1), Arc::clone(&host)).unwrap();
        let second = EvidencePool::new(capacity(1), host).unwrap();
        let held = acquire(&first).unwrap();
        assert!(acquire(&second).is_err());
        drop(held);
        assert!(acquire(&second).is_ok());
    }

    #[test]
    fn host_bytes_are_reserved_before_child_work_and_returned_with_slot() {
        let host =
            Arc::new(PostEffectEvidenceBudget::with_byte_limit(capacity(3), capacity(8)).unwrap());
        let first =
            EvidencePool::with_byte_limit(capacity(2), capacity(8), Arc::clone(&host)).unwrap();
        let second = EvidencePool::with_byte_limit(capacity(2), capacity(8), host).unwrap();
        let mut held = acquire(&first).unwrap();
        held.reserve_bytes(5).unwrap();
        let mut next = acquire(&second).unwrap();
        assert!(next.reserve_bytes(3).is_err());
        next.reserve_bytes(1).unwrap();
        drop(held);
        next.reserve_bytes(6).unwrap();
        assert!(next.reserve_bytes(1).is_err());
        drop(next);
        let mut restored = acquire(&first).unwrap();
        restored.reserve_bytes(7).unwrap();
    }

    #[test]
    fn oversized_capacity_is_refused_without_panicking() {
        let too_large = capacity(Semaphore::MAX_PERMITS + 1);
        assert!(PostEffectEvidenceBudget::new(too_large).is_err());
        assert!(EvidencePool::new(too_large, PostEffectEvidenceBudget::process_default()).is_err());
    }
}
